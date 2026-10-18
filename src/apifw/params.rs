//! Parameter values as the request carries them (strings) into the JSON values their schemas
//! describe, with a strict grammar: `1_000`, `0x1F` or `t` are not numbers or booleans here, and a
//! percent-escape that is not one makes the request invalid instead of being guessed at.

use serde_json::{Number, Value};

/// How a value is read, from the parameter's schema.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Kind {
    Integer,
    Number,
    Boolean,
    String,
    /// `null` allowed too (`nullable`, or `type: [x, "null"]`): an empty value is `null`.
    Nullable(Box<Kind>),
    Array(Box<Kind>),
    /// Anything else (objects, compositions): passed as a string, the schema decides.
    Other,
}

impl Kind {
    /// From a schema (references already followed by `resolve`).
    pub fn of(schema: &Value, resolve: &dyn Fn(&Value) -> Option<Value>) -> Kind {
        let schema = resolve(schema).unwrap_or_else(|| schema.clone());
        let types: Vec<&str> = match schema.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
            _ => return Kind::Other,
        };
        let nullable = types.contains(&"null");
        let kind = match types.iter().find(|t| **t != "null").copied() {
            Some("integer") => Kind::Integer,
            Some("number") => Kind::Number,
            Some("boolean") => Kind::Boolean,
            Some("string") => Kind::String,
            Some("array") => Kind::Array(Box::new(
                schema
                    .get("items")
                    .map_or(Kind::Other, |items| Kind::of(items, resolve)),
            )),
            _ => Kind::Other,
        };
        if nullable { Kind::Nullable(Box::new(kind)) } else { kind }
    }

    pub fn is_array(&self) -> bool {
        match self {
            Kind::Array(_) => true,
            Kind::Nullable(inner) => inner.is_array(),
            _ => false,
        }
    }

    /// One value; `None` when it does not read as the kind says.
    pub fn read(&self, raw: &str) -> Option<Value> {
        Some(match self {
            Kind::Integer => {
                let digits = raw.strip_prefix('-').unwrap_or(raw);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                match raw.parse::<i64>() {
                    Ok(n) => Value::Number(n.into()),
                    // Out of i64: still an integer, compared as a float by the schema.
                    Err(_) => Value::Number(Number::from_f64(raw.parse::<f64>().ok()?)?),
                }
            }
            Kind::Number => {
                if !is_json_number(raw) {
                    return None;
                }
                serde_json::from_str::<Value>(raw).ok()?
            }
            Kind::Boolean => match raw {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => return None,
            },
            Kind::Nullable(inner) if raw.is_empty() => {
                let _ = inner;
                Value::Null
            }
            Kind::Nullable(inner) => inner.read(raw)?,
            Kind::String | Kind::Other | Kind::Array(_) => Value::String(raw.to_string()),
        })
    }

    /// Several values of an array parameter.
    pub fn read_all<'a>(&self, raws: impl Iterator<Item = &'a str>) -> Option<Value> {
        let item = match self {
            Kind::Array(item) => item,
            Kind::Nullable(inner) => return inner.read_all(raws),
            _ => return None,
        };
        raws.map(|raw| item.read(raw))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array)
    }
}

/// JSON's number grammar (RFC 8259 §6), which OpenAPI numbers follow.
fn is_json_number(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = usize::from(b.first() == Some(&b'-'));
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > start
    };
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            digits(&mut i);
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        if !digits(&mut i) {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !digits(&mut i) {
            return false;
        }
    }
    i == b.len()
}

/// Percent-decoding that refuses broken escapes and text that is not UTF-8.
pub(super) fn decode_strict(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(text.to_string());
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |b: u8| (b as char).to_digit(16);
            let (hi, lo) = (hex(*bytes.get(i + 1)?)?, hex(*bytes.get(i + 2)?)?);
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A query string's pairs, decoded as forms are (`+` is a space); `None` when a part does not
/// decode.
pub(super) fn query_pairs(query: &str) -> Option<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for part in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        pairs.push((
            decode_strict(&key.replace('+', " "))?,
            decode_strict(&value.replace('+', " "))?,
        ));
    }
    Some(pairs)
}

/// The request's cookies, as `name=value` pairs.
pub(super) fn cookies(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            Some((name.to_string(), value.trim_matches('"').to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn values_read_strictly() {
        assert_eq!(Kind::Integer.read("42"), Some(json!(42)));
        assert_eq!(Kind::Integer.read("-7"), Some(json!(-7)));
        for bad in ["", "-", "1.0", "0x1F", "1_000", "+1", " 1", "1e3"] {
            assert_eq!(Kind::Integer.read(bad), None, "{bad:?}");
        }
        assert_eq!(Kind::Number.read("1.5e3"), Some(json!(1500.0)));
        assert_eq!(Kind::Number.read("-0.25"), Some(json!(-0.25)));
        for bad in ["", ".5", "1.", "01", "1e", "NaN", "Infinity", "1,5"] {
            assert_eq!(Kind::Number.read(bad), None, "{bad:?}");
        }
        assert_eq!(Kind::Boolean.read("true"), Some(json!(true)));
        for bad in ["t", "1", "TRUE", "yes"] {
            assert_eq!(Kind::Boolean.read(bad), None, "{bad:?}");
        }
        let nullable = Kind::Nullable(Box::new(Kind::Integer));
        assert_eq!(nullable.read(""), Some(Value::Null));
        assert_eq!(nullable.read("3"), Some(json!(3)));
        let ints = Kind::Array(Box::new(Kind::Integer));
        assert_eq!(ints.read_all(["1", "2"].into_iter()), Some(json!([1, 2])));
        assert_eq!(ints.read_all(["1", "x"].into_iter()), None);
    }

    #[test]
    fn kinds_follow_the_schema() {
        let none = |_: &Value| None;
        assert_eq!(Kind::of(&json!({"type": "integer"}), &none), Kind::Integer);
        assert_eq!(
            Kind::of(&json!({"type": ["string", "null"]}), &none),
            Kind::Nullable(Box::new(Kind::String))
        );
        assert_eq!(
            Kind::of(&json!({"type": "array", "items": {"type": "boolean"}}), &none),
            Kind::Array(Box::new(Kind::Boolean))
        );
        assert_eq!(Kind::of(&json!({"oneOf": []}), &none), Kind::Other);
        let resolve = |s: &Value| s.get("$ref").map(|_| json!({"type": "number"}));
        assert_eq!(Kind::of(&json!({"$ref": "#/x"}), &resolve), Kind::Number);
    }

    #[test]
    fn decoding_is_strict() {
        assert_eq!(decode_strict("a%20b").as_deref(), Some("a b"));
        assert_eq!(decode_strict("%D0%B4").as_deref(), Some("д"));
        for bad in ["%", "%2", "%zz", "%FF"] {
            assert_eq!(decode_strict(bad), None, "{bad:?}");
        }
        assert_eq!(
            query_pairs("a=1&b=x+y&c&&d=%3D").unwrap(),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "x y".into()),
                ("c".into(), String::new()),
                ("d".into(), "=".into())
            ]
        );
        assert!(query_pairs("a=%G1").is_none());
    }
}
