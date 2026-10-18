//! Request paths to operations: per method, a trie of path segments built from the spec's path
//! templates once. A segment is matched as a literal first, then as a template with literal parts
//! (`{name}.{ext}`, `v{version}`), then as a whole parameter (`{id}`); a deeper failure backtracks.
//! Case-sensitive and without folding of trailing slashes, as OpenAPI paths are.

use http::Method;
use rustc_hash::FxHashMap;
use std::sync::Arc;

#[derive(Default)]
pub(super) struct Router {
    roots: FxHashMap<Method, Node>,
}

#[derive(Default)]
struct Node {
    literal: FxHashMap<Box<str>, Node>,
    templates: Vec<(Template, Node)>,
    param: Option<(Arc<str>, Box<Node>)>,
    operation: Option<usize>,
}

/// A segment with literal parts and parameters, e.g. `{name}.{ext}`.
#[derive(PartialEq)]
struct Template {
    parts: Vec<Part>,
}

#[derive(PartialEq)]
enum Part {
    Literal(Box<str>),
    Param(Arc<str>),
}

/// What a request path matched: the operation and its path parameters (decoded).
pub(super) struct Found {
    pub operation: usize,
    pub params: Vec<(Arc<str>, String)>,
}

impl Router {
    /// Adds `operation` for `method` at the spec path `template` (`/orders/{id}`).
    pub fn add(&mut self, method: Method, template: &str, operation: usize) -> Result<(), String> {
        let mut node = self.roots.entry(method).or_default();
        for segment in segments(template) {
            node = match parse_segment(segment)? {
                Segment::Literal(text) => node.literal.entry(text.into()).or_default(),
                Segment::Param(name) => {
                    let (existing, child) = node.param.get_or_insert_with(|| (name.clone(), Box::default()));
                    if *existing != name {
                        return Err(format!(
                            "{template}: parameter {{{name}}} where another path has {{{existing}}}"
                        ));
                    }
                    child
                }
                Segment::Template(template) => {
                    let at = match node.templates.iter().position(|(t, _)| *t == template) {
                        Some(at) => at,
                        None => {
                            node.templates.push((template, Node::default()));
                            node.templates.len() - 1
                        }
                    };
                    &mut node.templates[at].1
                }
            };
        }
        if node.operation.replace(operation).is_some() {
            return Err(format!("{template}: defined twice"));
        }
        Ok(())
    }

    /// Whether any operation is defined for some method at this path.
    pub fn knows_path(&self, path: &str) -> bool {
        let parts: Vec<&str> = segments(path).collect();
        self.roots
            .values()
            .any(|root| root.find(&parts, &mut Vec::new()).is_some())
    }

    /// The operation for `method` at `path` (decoded), if any.
    pub fn find(&self, method: &Method, path: &str) -> Option<Found> {
        let root = self.roots.get(method)?;
        let parts: Vec<&str> = segments(path).collect();
        let mut params = Vec::new();
        let operation = root.find(&parts, &mut params)?;
        Some(Found { operation, params })
    }
}

impl Node {
    fn find(&self, segments: &[&str], params: &mut Vec<(Arc<str>, String)>) -> Option<usize> {
        let Some((segment, rest)) = segments.split_first() else {
            return self.operation;
        };
        if let Some(child) = self.literal.get(*segment)
            && let Some(found) = child.find(rest, params)
        {
            return Some(found);
        }
        for (template, child) in &self.templates {
            let mark = params.len();
            if template.capture(segment, params)
                && let Some(found) = child.find(rest, params)
            {
                return Some(found);
            }
            params.truncate(mark);
        }
        if let Some((name, child)) = &self.param
            && !segment.is_empty()
        {
            params.push((name.clone(), (*segment).to_string()));
            if let Some(found) = child.find(rest, params) {
                return Some(found);
            }
            params.pop();
        }
        None
    }
}

impl Template {
    /// Matches `segment` part by part: each literal at its first place after the previous part,
    /// each parameter non-empty.
    fn capture(&self, segment: &str, params: &mut Vec<(Arc<str>, String)>) -> bool {
        let mut rest = segment;
        let mut pending: Option<&Arc<str>> = None;
        for part in &self.parts {
            match part {
                Part::Literal(text) => {
                    let Some(at) = rest.find(&**text) else { return false };
                    match pending.take() {
                        Some(name) if at > 0 => params.push((name.clone(), rest[..at].to_string())),
                        Some(_) => return false,
                        None if at != 0 => return false,
                        None => {}
                    }
                    rest = &rest[at + text.len()..];
                }
                Part::Param(name) => pending = Some(name),
            }
        }
        match pending {
            Some(name) if !rest.is_empty() => {
                params.push((name.clone(), rest.to_string()));
                true
            }
            Some(_) => false,
            None => rest.is_empty(),
        }
    }
}

enum Segment {
    Literal(String),
    Param(Arc<str>),
    Template(Template),
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.strip_prefix('/').unwrap_or(path).split('/')
}

fn parse_segment(segment: &str) -> Result<Segment, String> {
    if !segment.contains('{') {
        return Ok(Segment::Literal(segment.to_string()));
    }
    let mut parts = Vec::new();
    let mut rest = segment;
    while let Some(open) = rest.find('{') {
        if open > 0 {
            parts.push(Part::Literal(rest[..open].into()));
        }
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| format!("unclosed {{ in {segment:?}"))?
            + open;
        let name = &rest[open + 1..close];
        if name.is_empty() || name.contains('{') {
            return Err(format!("invalid parameter in {segment:?}"));
        }
        if matches!(parts.last(), Some(Part::Param(_))) {
            return Err(format!("{segment:?}: two parameters with nothing between them"));
        }
        parts.push(Part::Param(name.into()));
        rest = &rest[close + 1..];
    }
    if !rest.is_empty() {
        parts.push(Part::Literal(rest.into()));
    }
    Ok(match parts.as_slice() {
        [Part::Param(name)] => Segment::Param(name.clone()),
        _ => Segment::Template(Template { parts }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        let mut r = Router::default();
        for (i, (method, path)) in [
            (Method::GET, "/orders"),
            (Method::GET, "/orders/{id}"),
            (Method::GET, "/orders/latest"),
            (Method::POST, "/orders"),
            (Method::GET, "/files/{name}.{ext}"),
            (Method::GET, "/v{version}/status"),
            (Method::GET, "/orders/{id}/items/{item}"),
            (Method::GET, "/a/"),
        ]
        .into_iter()
        .enumerate()
        {
            r.add(method, path, i).unwrap();
        }
        r
    }

    fn found(r: &Router, method: Method, path: &str) -> Option<(usize, Vec<(String, String)>)> {
        r.find(&method, path).map(|f| {
            (
                f.operation,
                f.params.into_iter().map(|(n, v)| (n.to_string(), v)).collect(),
            )
        })
    }

    #[test]
    fn paths_find_their_operations() {
        let r = router();
        assert_eq!(found(&r, Method::GET, "/orders"), Some((0, vec![])));
        assert_eq!(found(&r, Method::POST, "/orders"), Some((3, vec![])));
        assert_eq!(
            found(&r, Method::GET, "/orders/latest"),
            Some((2, vec![])),
            "literal first"
        );
        assert_eq!(
            found(&r, Method::GET, "/orders/42"),
            Some((1, vec![("id".into(), "42".into())]))
        );
        assert_eq!(
            found(&r, Method::GET, "/orders/7/items/9"),
            Some((6, vec![("id".into(), "7".into()), ("item".into(), "9".into())]))
        );
        assert_eq!(
            found(&r, Method::GET, "/files/report.v2.pdf"),
            Some((
                4,
                vec![("name".into(), "report".into()), ("ext".into(), "v2.pdf".into())]
            ))
        );
        assert_eq!(
            found(&r, Method::GET, "/v2/status"),
            Some((5, vec![("version".into(), "2".into())]))
        );
        assert_eq!(found(&r, Method::GET, "/a/"), Some((7, vec![])));
        for (method, path) in [
            (Method::DELETE, "/orders"),
            (Method::GET, "/orders/"),
            (Method::GET, "/Orders"),
            (Method::GET, "/a"),
            (Method::GET, "/files/noext"),
            (Method::GET, "/files/.pdf"),
            (Method::GET, "/v/status"),
            (Method::GET, "/orders/7/items"),
            (Method::GET, "/orders//items/9"),
        ] {
            assert!(found(&r, method.clone(), path).is_none(), "{method} {path}");
        }
        assert!(r.knows_path("/orders"));
        assert!(!r.knows_path("/nothing"));
    }

    #[test]
    fn inconsistent_templates_are_refused() {
        let mut r = Router::default();
        r.add(Method::GET, "/a/{id}", 0).unwrap();
        assert!(
            r.add(Method::GET, "/a/{name}/x", 1)
                .unwrap_err()
                .contains("another path")
        );
        assert!(r.add(Method::GET, "/a/{id}", 2).unwrap_err().contains("twice"));
        assert!(r.add(Method::GET, "/b/{x", 3).is_err());
        assert!(r.add(Method::GET, "/b/{x}{y}", 4).is_err());
    }
}
