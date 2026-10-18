//! An OpenAPI 3.0 / 3.1 document compiled for checking requests: a router to operations, and for
//! each operation its parameters and request bodies with validators compiled once (jsonschema,
//! JSON Schema 2020-12; patterns with the linear-time `regex` engine, so a pattern cannot be made
//! to backtrack). OpenAPI 3.0 schemas are converted first: `nullable`, the boolean
//! `exclusiveMinimum` / `exclusiveMaximum`, `int32` bounds, and `readOnly` properties, which a
//! request may not send. With strict bodies, objects take no properties their schema does not
//! name (`unevaluatedProperties: false` on schemas that are not members of an allOf / anyOf /
//! oneOf, so compositions keep working).
//!
//! References inside schemas are resolved by jsonschema against the whole document; those that
//! structure the document (parameters, request bodies, path items) are followed here. References
//! to other files or URLs are not supported.

use super::params::Kind;
use super::router::Router;
use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderName, Method};
use jsonschema::{Draft, PatternOptions, Registry, Resource, Validator};
use rustc_hash::FxHashSet;
use serde_json::{Map, Value, json};
use std::path::Path;

/// The document's URI for references from compiled schemas.
const DOCUMENT: &str = "urn:openapi";

pub(super) struct Spec {
    pub router: Router,
    pub operations: Vec<Operation>,
}

pub(super) struct Operation {
    pub method: Method,
    /// The path template, as written in the spec.
    pub path: String,
    pub params: Vec<Param>,
    pub body: Option<RequestBody>,
    /// Alternatives (any one will do), each a set of credentials that must all be present;
    /// empty: none needed.
    pub security: Vec<Vec<Credential>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Location {
    Path,
    Query,
    Header,
    Cookie,
}

pub(super) struct Param {
    /// Header names in lowercase.
    pub name: String,
    pub location: Location,
    pub required: bool,
    pub allow_empty: bool,
    /// Query arrays sent as repeated parameters (`form` with `explode`).
    pub repeated: bool,
    /// How array items are separated in one value.
    pub separator: char,
    /// `content: application/json`: the value is JSON.
    pub json: bool,
    pub kind: Kind,
    /// `None`: the style is not supported; only presence is checked.
    pub validator: Option<Validator>,
}

pub(super) struct RequestBody {
    pub required: bool,
    pub media: Vec<Media>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyFormat {
    Json,
    Form,
    Text,
    /// Declared but not looked into (multipart, binary, XML…): its type and size are checked.
    Unchecked,
}

pub(super) struct Media {
    /// Lowercase, without parameters: `application/json`, `application/*` or `*/*`.
    pub range: String,
    pub format: BodyFormat,
    pub validator: Option<Validator>,
    /// Form fields and how their values read.
    pub fields: Vec<(String, Kind)>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Credential {
    /// A header, starting with the scheme (lowercase, `bearer `) when given.
    Header(HeaderName, Option<String>),
    Query(String),
    Cookie(String),
    /// Something a request cannot show (mutual TLS): taken as present.
    Unverifiable,
}

impl Media {
    /// Whether the body's media type (lowercase, without parameters) falls in this range.
    pub fn accepts(&self, media_type: &str) -> bool {
        match self.range.as_str() {
            "*/*" => true,
            range => match range.strip_suffix("/*") {
                Some(kind) => media_type.split('/').next() == Some(kind),
                None => range == media_type,
            },
        }
    }
}

impl RequestBody {
    /// The declaration for a media type: an exact one before a range, before `*/*`.
    pub fn find(&self, media_type: &str) -> Option<&Media> {
        let specificity = |m: &&Media| match m.range.as_str() {
            "*/*" => 2,
            r if r.ends_with("/*") => 1,
            _ => 0,
        };
        self.media
            .iter()
            .filter(|m| m.accepts(media_type))
            .min_by_key(specificity)
    }
}

/// Reads the document at `path` (YAML, or JSON for `.json`).
pub(super) fn load(path: &Path, strict: bool) -> Result<Spec> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let document: Value = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json")) {
        serde_json::from_str(&text)?
    } else {
        serde_yaml_ng::from_str(&text)?
    };
    compile(document, strict).with_context(|| format!("OpenAPI document {}", path.display()))
}

pub(super) fn compile(mut document: Value, strict: bool) -> Result<Spec> {
    let version = document
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("not an OpenAPI 3 document (no `openapi` version)"))?
        .to_string();
    let v30 = version.starts_with("3.0");
    if !v30 && !version.starts_with("3.1") {
        bail!("OpenAPI {version} is not supported (3.0 and 3.1 are)");
    }
    convert_document(&mut document, v30, strict);
    let registry = Registry::new()
        .draft(Draft::Draft202012)
        .add(DOCUMENT, Resource::from_contents(document.clone()))
        .map_err(|e| anyhow!("{e}"))?
        .prepare()
        .map_err(|e| anyhow!("{e}"))?;
    let options = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_registry(&registry)
        .should_validate_formats(true)
        .with_pattern_options(PatternOptions::regex());
    let compiler = |schema: &Value| -> Result<Validator> {
        options
            .build(&absolute(schema.clone()))
            .map_err(|e| anyhow!("schema: {e}"))
    };
    let doc = &document;
    let mut spec = Spec {
        router: Router::default(),
        operations: Vec::new(),
    };
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Ok(spec);
    };
    for (path, item) in paths {
        let item = follow(doc, item).with_context(|| format!("path {path}"))?;
        let shared = item
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for name in ["get", "put", "post", "delete", "options", "head", "patch", "trace"] {
            let Some(op) = item.get(name) else { continue };
            let method = Method::from_bytes(name.to_ascii_uppercase().as_bytes()).expect("a method");
            let operation = operation(doc, path, method.clone(), &shared, op, &compiler)
                .with_context(|| format!("{} {path}", name.to_ascii_uppercase()))?;
            spec.router
                .add(method, path, spec.operations.len())
                .map_err(|e| anyhow!(e))?;
            spec.operations.push(operation);
        }
    }
    Ok(spec)
}

fn operation(
    doc: &Value,
    path: &str,
    method: Method,
    shared: &[Value],
    op: &Value,
    compiler: &dyn Fn(&Value) -> Result<Validator>,
) -> Result<Operation> {
    // The operation's parameters replace path-level ones of the same name and place.
    let mut declared: Vec<&Value> = Vec::new();
    for p in op
        .get("parameters")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .chain(shared)
    {
        let p = follow(doc, p)?;
        let key = (p.get("name"), p.get("in"));
        if !declared.iter().any(|d| (d.get("name"), d.get("in")) == key) {
            declared.push(p);
        }
    }
    let mut params = Vec::new();
    for p in declared {
        params.push(param(doc, p, compiler)?);
    }
    for p in params.iter().filter(|p| p.location == Location::Path) {
        if !path.contains(&format!("{{{}}}", p.name)) {
            bail!("path parameter {} is not in the path", p.name);
        }
    }
    let body = match op.get("requestBody") {
        Some(body) => Some(request_body(doc, follow(doc, body)?, compiler)?),
        None => None,
    };
    let security = match op.get("security").or_else(|| doc.get("security")) {
        Some(requirements) => security(doc, requirements)?,
        None => Vec::new(),
    };
    Ok(Operation {
        method,
        path: path.to_string(),
        params,
        body,
        security,
    })
}

fn param(doc: &Value, p: &Value, compiler: &dyn Fn(&Value) -> Result<Validator>) -> Result<Param> {
    let name = p
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("a parameter without a name"))?;
    let location = match p.get("in").and_then(Value::as_str) {
        Some("path") => Location::Path,
        Some("query") => Location::Query,
        Some("header") => Location::Header,
        Some("cookie") => Location::Cookie,
        other => bail!("parameter {name}: `in` {other:?}"),
    };
    let flag = |key: &str| p.get(key).and_then(Value::as_bool).unwrap_or(false);
    let style = p.get("style").and_then(Value::as_str).unwrap_or(match location {
        Location::Query | Location::Cookie => "form",
        Location::Path | Location::Header => "simple",
    });
    let explode = p.get("explode").and_then(Value::as_bool).unwrap_or(style == "form");
    let (schema, json) = match (p.get("schema"), p.get("content").and_then(Value::as_object)) {
        (Some(schema), _) => (schema.clone(), false),
        (None, Some(content)) => {
            let schema = content
                .get("application/json")
                .and_then(|m| m.get("schema"))
                .cloned()
                .unwrap_or(json!({}));
            (schema, true)
        }
        (None, None) => (json!({}), false),
    };
    let kind = Kind::of(&schema, &|s| follow(doc, s).ok().cloned());
    let (separator, supported) = match (style, location) {
        ("form" | "simple", _) => (',', true),
        ("spaceDelimited", Location::Query) => (' ', true),
        ("pipeDelimited", Location::Query) => ('|', true),
        _ => (',', false),
    };
    if !supported {
        tracing::warn!(
            parameter = name,
            style,
            "OpenAPI parameter style not supported: only its presence is checked"
        );
    }
    Ok(Param {
        name: if location == Location::Header {
            name.to_ascii_lowercase()
        } else {
            name.to_string()
        },
        location,
        required: location == Location::Path || flag("required"),
        allow_empty: flag("allowEmptyValue"),
        repeated: location == Location::Query && style == "form" && explode,
        separator,
        json,
        kind,
        validator: if supported {
            Some(compiler(&schema).with_context(|| format!("parameter {name}"))?)
        } else {
            None
        },
    })
}

fn request_body(doc: &Value, body: &Value, compiler: &dyn Fn(&Value) -> Result<Validator>) -> Result<RequestBody> {
    let mut media = Vec::new();
    if let Some(content) = body.get("content").and_then(Value::as_object) {
        for (media_type, declaration) in content {
            let range = media_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            let format = if range == "application/json" || range.ends_with("+json") {
                BodyFormat::Json
            } else if range == "application/x-www-form-urlencoded" {
                BodyFormat::Form
            } else if range == "text/plain" {
                BodyFormat::Text
            } else {
                BodyFormat::Unchecked
            };
            let schema = declaration.get("schema");
            let validator = match (schema, format) {
                (Some(schema), BodyFormat::Json | BodyFormat::Form | BodyFormat::Text) => {
                    Some(compiler(schema).with_context(|| format!("request body {media_type}"))?)
                }
                _ => None,
            };
            let mut fields = Vec::new();
            if format == BodyFormat::Form
                && let Some(schema) = schema
                && let Some(properties) = follow(doc, schema)?.get("properties").and_then(Value::as_object)
            {
                for (name, property) in properties {
                    fields.push((name.clone(), Kind::of(property, &|s| follow(doc, s).ok().cloned())));
                }
            }
            if format == BodyFormat::Unchecked {
                tracing::info!(media_type = %media_type, "OpenAPI request body type not validated (its type and size are)");
            }
            media.push(Media {
                range,
                format,
                validator,
                fields,
            });
        }
    }
    Ok(RequestBody {
        required: body.get("required").and_then(Value::as_bool).unwrap_or(false),
        media,
    })
}

fn security(doc: &Value, requirements: &Value) -> Result<Vec<Vec<Credential>>> {
    let Some(requirements) = requirements.as_array() else {
        bail!("security: a list of requirements");
    };
    let schemes = doc.pointer("/components/securitySchemes");
    let mut out = Vec::new();
    for requirement in requirements {
        let Some(requirement) = requirement.as_object() else {
            bail!("security: a requirement is an object");
        };
        let mut all = Vec::new();
        for name in requirement.keys() {
            let scheme = schemes
                .and_then(|s| s.get(name))
                .ok_or_else(|| anyhow!("security scheme {name} is not defined"))?;
            let scheme = follow(doc, scheme)?;
            let text = |key: &str| scheme.get(key).and_then(Value::as_str).unwrap_or("");
            all.push(match text("type") {
                "apiKey" => match text("in") {
                    "header" => Credential::Header(
                        HeaderName::from_bytes(text("name").as_bytes())
                            .map_err(|_| anyhow!("security scheme {name}: header name"))?,
                        None,
                    ),
                    "query" => Credential::Query(text("name").to_string()),
                    "cookie" => Credential::Cookie(text("name").to_string()),
                    other => bail!("security scheme {name}: apiKey in {other:?}"),
                },
                "http" => Credential::Header(
                    http::header::AUTHORIZATION,
                    Some(format!("{} ", text("scheme").to_ascii_lowercase())),
                ),
                "oauth2" | "openIdConnect" => Credential::Header(http::header::AUTHORIZATION, Some("bearer ".into())),
                "mutualTLS" => Credential::Unverifiable,
                other => bail!("security scheme {name}: type {other:?}"),
            });
        }
        out.push(all);
    }
    // `security: []`, or a requirement `{}`: nothing is needed.
    if out.is_empty() || out.iter().any(Vec::is_empty) {
        return Ok(Vec::new());
    }
    Ok(out)
}

/// Follows `$ref`s within the document (JSON pointers, percent-escapes allowed).
pub(super) fn follow<'a>(doc: &'a Value, mut value: &'a Value) -> Result<&'a Value> {
    for _ in 0..32 {
        let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
            return Ok(value);
        };
        let pointer = reference
            .strip_prefix('#')
            .ok_or_else(|| anyhow!("$ref {reference}: only references within the document are supported"))?;
        let pointer = percent_encoding::percent_decode_str(pointer).decode_utf8_lossy();
        value = doc
            .pointer(&pointer)
            .ok_or_else(|| anyhow!("$ref {reference}: not found"))?;
    }
    bail!("$ref chain too long (a cycle?)")
}

/// The schema with its in-document references made absolute, to compile on its own.
fn absolute(mut schema: Value) -> Value {
    fn walk(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get_mut("$ref")
                    && reference.starts_with('#')
                {
                    *reference = format!("{DOCUMENT}{reference}");
                }
                map.values_mut().for_each(walk);
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut schema);
    schema
}

/// Every schema of the document converted (see the module documentation).
fn convert_document(doc: &mut Value, v30: bool, strict: bool) {
    let members = composition_members(doc);
    if let Some(Value::Object(schemas)) = doc.pointer_mut("/components/schemas") {
        for (name, schema) in schemas.iter_mut() {
            convert_schema(schema, v30, strict, members.contains(name));
        }
    }
    let Value::Object(root) = doc else { return };
    let mut holders: Vec<&mut Value> = Vec::new();
    for (section, value) in root.iter_mut() {
        match (section.as_str(), value) {
            ("components", Value::Object(components)) => {
                for (kind, group) in components.iter_mut() {
                    if matches!(kind.as_str(), "parameters" | "requestBodies" | "headers")
                        && let Value::Object(group) = group
                    {
                        holders.extend(group.values_mut());
                    }
                }
            }
            ("paths", Value::Object(paths)) => collect_holders(paths, &mut holders),
            _ => {}
        }
    }
    for holder in holders {
        // A parameter or header (`schema`, or `content`) or a request body (`content`).
        if let Some(schema) = holder.get_mut("schema") {
            convert_schema(schema, v30, strict, false);
        }
        if let Some(Value::Object(content)) = holder.get_mut("content") {
            for media in content.values_mut() {
                if let Some(schema) = media.get_mut("schema") {
                    convert_schema(schema, v30, strict, false);
                }
            }
        }
    }
}

/// The parameters and request bodies of the paths' operations.
fn collect_holders<'a>(paths: &'a mut Map<String, Value>, holders: &mut Vec<&'a mut Value>) {
    {
        for item in paths.values_mut() {
            let Value::Object(item) = item else { continue };
            for (key, value) in item.iter_mut() {
                match key.as_str() {
                    "parameters" => {
                        if let Value::Array(list) = value {
                            holders.extend(list.iter_mut());
                        }
                    }
                    "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace" => {
                        if let Value::Object(op) = value {
                            for (key, value) in op.iter_mut() {
                                match (key.as_str(), value) {
                                    ("parameters", Value::Array(list)) => holders.extend(list.iter_mut()),
                                    ("requestBody", body) => holders.push(body),
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Component schemas used as members of an allOf / anyOf / oneOf somewhere.
fn composition_members(doc: &Value) -> FxHashSet<String> {
    fn walk(value: &Value, out: &mut FxHashSet<String>) {
        match value {
            Value::Object(map) => {
                for key in ["allOf", "anyOf", "oneOf"] {
                    if let Some(Value::Array(list)) = map.get(key) {
                        for member in list {
                            if let Some(name) = member
                                .get("$ref")
                                .and_then(Value::as_str)
                                .and_then(|r| r.strip_prefix("#/components/schemas/"))
                            {
                                out.insert(name.to_string());
                            }
                        }
                    }
                }
                map.values().for_each(|v| walk(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = FxHashSet::default();
    walk(doc, &mut out);
    out
}

fn convert_schema(schema: &mut Value, v30: bool, strict: bool, member: bool) {
    let Value::Object(map) = schema else { return };
    if map.contains_key("$ref") {
        // OpenAPI 3.0 ignores a reference's siblings; 3.1 keeps them, as JSON Schema does.
        return;
    }
    if v30 {
        if map.remove("nullable") == Some(Value::Bool(true)) {
            if let Some(Value::String(kind)) = map.get("type").cloned() {
                map.insert("type".into(), json!([kind, "null"]));
            }
            if let Some(Value::Array(values)) = map.get_mut("enum")
                && !values.contains(&Value::Null)
            {
                values.push(Value::Null);
            }
        }
        for (flag, bound) in [("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")] {
            match map.get(flag) {
                Some(Value::Bool(true)) => match map.remove(bound) {
                    Some(value) => {
                        map.insert(flag.into(), value);
                    }
                    None => {
                        map.remove(flag);
                    }
                },
                Some(Value::Bool(false)) => {
                    map.remove(flag);
                }
                _ => {}
            }
        }
    }
    if map.get("format").and_then(Value::as_str) == Some("int32") {
        map.entry("minimum").or_insert(json!(i32::MIN));
        map.entry("maximum").or_insert(json!(i32::MAX));
    }
    if let Some(Value::Object(properties)) = map.get_mut("properties") {
        let read_only: Vec<String> = properties
            .iter()
            .filter(|(_, s)| s.get("readOnly") == Some(&Value::Bool(true)))
            .map(|(name, _)| name.clone())
            .collect();
        for name in &read_only {
            properties.insert(name.clone(), Value::Bool(false));
        }
        if !read_only.is_empty()
            && let Some(Value::Array(required)) = map.get_mut("required")
        {
            required.retain(|r| !read_only.iter().any(|n| r == n));
        }
    }
    for key in ["properties", "patternProperties", "$defs", "dependentSchemas"] {
        if let Some(Value::Object(children)) = map.get_mut(key) {
            for child in children.values_mut() {
                convert_schema(child, v30, strict, false);
            }
        }
    }
    for key in [
        "items",
        "not",
        "additionalProperties",
        "unevaluatedProperties",
        "unevaluatedItems",
        "contains",
        "propertyNames",
        "if",
        "then",
        "else",
    ] {
        if let Some(child) = map.get_mut(key) {
            convert_schema(child, v30, strict, false);
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(Value::Array(children)) = map.get_mut(key) {
            for child in children {
                convert_schema(child, v30, strict, key != "prefixItems");
            }
        }
    }
    let object_like = map.contains_key("properties")
        || map.contains_key("allOf")
        || map.contains_key("anyOf")
        || map.contains_key("oneOf");
    if strict
        && !member
        && object_like
        && !map.contains_key("additionalProperties")
        && !map.contains_key("unevaluatedProperties")
    {
        map.insert("unevaluatedProperties".into(), Value::Bool(false));
    }
}
