//! YAML as the extensions read it: the JWT and API firewall files and OpenAPI specs (src/jwt,
//! src/apifw), with serde-saphyr. Read as serde_yaml_ng read them before it: YAML 1.2 booleans
//! (`off`, `yes` stay strings), `0755` and `1_000` strings, a repeated key the last one, `<<` an
//! ordinary key, `.inf` and `.nan` null in a JSON value, an unknown tag an error; one-line errors,
//! without the document's lines (a file may hold secrets).
//!
//! The limits on what a document may expand to are serde-saphyr's own (aliases, anchors, merge
//! keys) but for its size: nodes and events are bounded by the length of the text, which its
//! readers bound (an OpenAPI spec: 10 MiB), so a large spec is read whole and an alias bomb is
//! still refused. Nesting: 128 levels, serde_yaml_ng's limit.

use serde::de::DeserializeOwned;
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy};

pub use serde_saphyr::Error;

/// `text` as `T`.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    // A node or an event takes a byte of the text at least; aliases replay events under their
    // own limits.
    let size = text.len().saturating_add(64);
    let budget = serde_saphyr::budget! {
        max_reader_input_bytes: Some(size),
        max_events: size.saturating_mul(2),
        max_nodes: size,
        max_depth: 128,
    };
    let options = serde_saphyr::options! {
        budget: budget,
        strict_booleans: true,
        leading_zero_numbers_as_strings: true,
        underscored_numbers_as_strings: true,
        duplicate_keys: DuplicateKeyPolicy::LastWins,
        merge_keys: MergeKeyPolicy::AsOrdinary,
        non_finite_float_policy: NonFiniteFloatPolicy::PassThrough,
        reject_unsupported_tags: true,
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(text, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn read(text: &str) -> Value {
        from_str(text).unwrap()
    }

    #[test]
    fn scalars_are_read_as_yaml_1_2() {
        assert_eq!(
            read("a: off\nb: yes\nc: on\nd: True\ne: FALSE\n"),
            json!({"a": "off", "b": "yes", "c": "on", "d": true, "e": false})
        );
        assert_eq!(
            read("a: 0755\nb: 0o755\nc: 0x1F\nd: 1e3\ne: 1_000\nf: +12\ng: 9223372036854775808\n"),
            json!({"a": "0755", "b": 493, "c": 31, "d": 1000.0, "e": "1_000", "f": 12, "g": 9223372036854775808u64})
        );
        assert_eq!(
            read("a: ~\nb: null\nc:\nd: ''\ne: .inf\nf: .nan\ng: 2026-11-04\nh: 10:30\n"),
            json!({"a": null, "b": null, "c": null, "d": "", "e": null, "f": null, "g": "2026-11-04", "h": "10:30"})
        );
    }

    #[test]
    fn keys_aliases_and_tags_as_before() {
        assert_eq!(read("a: 1\na: 2\n"), json!({"a": 2}), "the last of a repeated key");
        assert_eq!(
            read("base: &b {x: 1}\nuse: *b\nmerged:\n  <<: *b\n  y: 2\n"),
            json!({"base": {"x": 1}, "use": {"x": 1}, "merged": {"<<": {"x": 1}, "y": 2}}),
            "an alias is its anchor's value; `<<` is an ordinary key"
        );
        assert_eq!(read("a: !!str 123\n"), json!({"a": "123"}));
        assert!(from_str::<Value>("a: !custom value\n").is_err(), "an unknown tag");
        assert!(from_str::<Value>("a: 1\n---\nb: 2\n").is_err(), "two documents");
    }

    #[test]
    fn an_empty_document_is_null() {
        // serde-saphyr 2.1.0 refused these (yanked for it).
        for text in ["", "\n", "# a comment\n", "---\n"] {
            assert_eq!(read(text), Value::Null, "{text:?}");
        }
    }

    #[test]
    fn errors_are_one_line_without_the_text() {
        let error = from_str::<Value>("token: s3cret\nlist:\n\t- 1\n")
            .unwrap_err()
            .to_string();
        assert!(!error.contains('\n') && !error.contains("s3cret"), "{error}");
        assert!(error.contains("line 3"), "{error}");
    }

    #[test]
    fn a_large_document_is_read_and_an_alias_bomb_is_not() {
        let mut large = String::from("paths:\n");
        for i in 0..70_000 {
            large.push_str(&format!("  /p{i}: {{get: {{x: 1}}}}\n"));
        }
        assert_eq!(read(&large)["paths"].as_object().unwrap().len(), 70_000);

        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..10 {
            let previous = (b'a' + level - 1) as char;
            let name = (b'a' + level) as char;
            bomb.push_str(&format!("{name}: &{name} [*{previous}, *{previous}, *{previous}, *{previous}, *{previous}, *{previous}, *{previous}, *{previous}, *{previous}, *{previous}]\n"));
        }
        assert!(
            from_str::<Value>(&bomb).is_err(),
            "10^10 nodes from a few hundred bytes"
        );
    }
}
