//! Just enough JSON serialization for stats records, without pulling in a
//! serialization framework for one output format.

use std::fmt::Write;

/// A JSON value. Objects keep insertion order.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Int(u64),
    /// Written rounded to 2 decimals, like `dnsstat.py`'s `round(x, 2)`;
    /// non-finite values become `null`.
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Builds an object from `(key, value)` pairs.
    pub fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Value)>) -> Self {
        Self::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Builds an object of counters.
    pub fn counts<K: AsRef<str>>(entries: impl IntoIterator<Item = (K, u64)>) -> Self {
        Self::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_owned(), Self::Int(v)))
                .collect(),
        )
    }

    /// Serializes compactly, like `json.dumps(..., separators=(",", ":"))`.
    pub fn to_compact_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Self::Float(x) if x.is_finite() => {
                let rounded = (x * 100.0).round() / 100.0;
                let _ = write!(out, "{rounded}");
            }
            Self::Float(_) => out.push_str("null"),
            Self::String(s) => write_string(out, s),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(out, key);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_compact_json() {
        let v = Value::object([
            ("a", Value::Int(1)),
            ("b", Value::Float(1.0 / 3.0)),
            ("c", Value::String("q\"\\\n\u{1}".into())),
            ("d", Value::Array(vec![Value::Null, Value::Float(f64::NAN)])),
            ("e", Value::counts([("x", 2)])),
        ]);
        assert_eq!(
            v.to_compact_string(),
            r#"{"a":1,"b":0.33,"c":"q\"\\\n\u0001","d":[null,null],"e":{"x":2}}"#
        );
    }
}
