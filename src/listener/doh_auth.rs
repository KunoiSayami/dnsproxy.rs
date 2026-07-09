//! HTTP Basic Auth credential checking for the DoH/DoH3 listeners: requests
//! must present one of a configured set of `username:password` credentials
//! in the `Authorization` header, mirroring how the DoH *client* already
//! sends Basic Auth (`doh.rs`'s `basic_auth_header`) but on the receiving
//! side instead.

use base64::Engine;

/// A set of valid `username:password` credentials for the DoH/DoH3
/// listeners. Any one matching pair authenticates a request; all
/// authenticated requests are treated identically (no per-user routing).
#[derive(Default)]
pub struct Credentials {
    // Stored pre-encoded (`Basic <base64>`) so each request only needs a
    // cheap string comparison against the raw `Authorization` header value,
    // not a decode-then-compare.
    valid_headers: Vec<String>,
}

impl Credentials {
    /// Builds a credential set from `user:password` pairs, e.g. as parsed
    /// from repeated `--doh-auth` flags or lines of a `--doh-auth-file`.
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let valid_headers = pairs
            .into_iter()
            .map(|(user, pass)| {
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
                format!("Basic {encoded}")
            })
            .collect();
        Self { valid_headers }
    }

    /// Whether this credential set has any entries. An empty set means
    /// auth-checking is disabled entirely (callers should skip the check).
    pub fn is_empty(&self) -> bool {
        self.valid_headers.is_empty()
    }

    /// Checks whether `authorization` (the raw `Authorization` header value,
    /// if present) matches one of the configured credentials.
    pub fn is_authorized(&self, authorization: Option<&str>) -> bool {
        match authorization {
            Some(header) => self.valid_headers.iter().any(|valid| valid == header),
            None => false,
        }
    }

    /// Parses one `user:password` pair, as given on the `--doh-auth` flag or
    /// one line of `--doh-auth-file`.
    pub fn parse_pair(s: &str) -> Result<(String, String), String> {
        let (user, pass) = s
            .split_once(':')
            .ok_or_else(|| format!("invalid credential {s:?}: expected user:password"))?;
        if user.is_empty() {
            return Err(format!("invalid credential {s:?}: username is empty"));
        }
        Ok((user.to_owned(), pass.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_any_configured_pair() {
        let creds = Credentials::new([
            ("alice".to_owned(), "secret1".to_owned()),
            ("bob".to_owned(), "secret2".to_owned()),
        ]);

        let alice_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:secret1")
        );
        let bob_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("bob:secret2")
        );

        assert!(creds.is_authorized(Some(&alice_header)));
        assert!(creds.is_authorized(Some(&bob_header)));
    }

    #[test]
    fn rejects_wrong_or_missing_credentials() {
        let creds = Credentials::new([("alice".to_owned(), "secret1".to_owned())]);

        let wrong_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:wrong")
        );
        assert!(!creds.is_authorized(Some(&wrong_header)));
        assert!(!creds.is_authorized(None));
    }

    #[test]
    fn empty_credential_set_is_empty() {
        let creds = Credentials::new([]);
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_pair_splits_on_first_colon() {
        let (user, pass) = Credentials::parse_pair("alice:pass:with:colons").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "pass:with:colons");
    }

    #[test]
    fn parse_pair_rejects_missing_colon() {
        assert!(Credentials::parse_pair("no-colon-here").is_err());
    }
}
