//! Enforce a nesting limit even in JSON fields ignored by typed deserializers.
//! Callers must also bound the input bytes and the time spent receiving them.
use serde::Deserialize;

const MAX_DEPTH: usize = 128;

fn check_depth(bytes: &[u8]) -> serde_json::Result<()> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(serde_json::Error::io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "JSON nesting exceeds 128 containers",
                        )));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    // Syntax, UTF-8, and matching delimiters are checked by serde_json below.
    Ok(())
}

pub fn from_slice<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> serde_json::Result<T> {
    check_depth(bytes)?;
    serde_json::from_slice(bytes)
}

pub fn from_str<'a, T: Deserialize<'a>>(text: &'a str) -> serde_json::Result<T> {
    check_depth(text.as_bytes())?;
    serde_json::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Document {
        known: bool,
    }

    #[test]
    fn ignored_fields_have_the_same_depth_limit_as_materialized_values() {
        let text = format!(
            "{{\"known\":true,\"ignored\":{}0{}}}",
            "[".repeat(129),
            "]".repeat(129)
        );
        // serde_json skips unknown fields without its usual recursion check.
        assert!(serde_json::from_str::<Document>(&text).unwrap().known);
        assert!(from_str::<Document>(&text).is_err());
        assert!(from_slice::<Document>(text.as_bytes()).is_err());
        assert!(from_str::<serde_json::Value>(&text).is_err());
    }

    #[test]
    fn escaped_quotes_and_brackets_in_strings_do_not_change_depth() {
        let value = serde_json::json!({"known":true,"text": "\"\\[]{}".repeat(256)});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(from_slice::<Document>(&bytes).unwrap().known);
        for bytes in [b"{]".as_slice(), b"{} trailing", b"\"unterminated"] {
            assert!(from_slice::<serde_json::Value>(bytes).is_err());
        }
        let text = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(from_str::<serde_json::Value>(&text).is_ok());
    }
}
