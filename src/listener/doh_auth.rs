//! HTTP Basic Auth credential checking for the DoH/DoH3 listeners: requests
//! must present one of a configured set of `username:password` credentials
//! in the `Authorization` header, mirroring how the DoH *client* already
//! sends Basic Auth (`doh.rs`'s `basic_auth_header`) but on the receiving
//! side instead.

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

/// Go's `base64.StdEncoding`: padding required, but unlike the `base64`
/// crate's `STANDARD`, non-zero unused bits in the last character are
/// accepted (Go only rejects them in `Strict` mode).
const GO_STD_ENCODING: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// A set of valid `username:password` credentials for the DoH/DoH3
/// listeners. Any one matching pair authenticates a request; all
/// authenticated requests are treated identically (no per-user routing).
#[derive(Default)]
pub struct Credentials {
    pairs: Vec<(String, String)>,
}

impl Credentials {
    /// Builds a credential set from `user:password` pairs, e.g. as parsed
    /// from repeated `--doh-auth` flags or lines of a `--doh-auth-file`.
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            pairs: pairs.into_iter().collect(),
        }
    }

    /// Whether this credential set has any entries. An empty set means
    /// auth-checking is disabled entirely (callers should skip the check).
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Checks whether `authorization` (the raw `Authorization` header value,
    /// if present) carries one of the configured credentials, parsed as Go's
    /// `Request.BasicAuth` does (see [`parse_basic_auth`]).
    pub fn is_authorized(&self, authorization: Option<&str>) -> bool {
        authorization
            .and_then(parse_basic_auth)
            .is_some_and(|(user, pass)| {
                self.pairs.iter().any(|(u, p)| {
                    u.as_bytes() == user.as_slice() && p.as_bytes() == pass.as_slice()
                })
            })
    }

    /// Parses one `user:password` pair, as given on the `--doh-auth` flag or
    /// one line of `--doh-auth-file`.
    ///
    /// A pair wrapped in matching quotes (`'alice:secret'`) is accepted as
    /// is, quotes included, but logs a warning: it's usually a value copied
    /// from a shell command or systemd unit, where the quotes were syntax.
    /// They aren't stripped, since a password may really end in a quote.
    pub fn parse_pair(s: &str) -> Result<(String, String), String> {
        let (user, pass) = s
            .split_once(':')
            .ok_or_else(|| format!("invalid credential {s:?}: expected user:password"))?;
        if user.is_empty() {
            return Err(format!("invalid credential {s:?}: username is empty"));
        }
        if is_quoted(s) {
            // Never the password, and only the first character of the user.
            let initial = user.chars().nth(1).unwrap_or_default();
            tracing::warn!(
                "credential for user {initial}… is wrapped in quotes; the quotes are part of \
                 the username and password"
            );
        }
        Ok((user.to_owned(), pass.to_owned()))
    }
}

/// Whether `s` starts and ends with the same quote character, `'` or `"`.
fn is_quoted(s: &str) -> bool {
    ['\'', '"']
        .into_iter()
        .any(|q| s.len() >= 2 && s.starts_with(q) && s.ends_with(q))
}

/// Splits a Basic Auth header into user and password, mirroring Go's
/// `net/http.parseBasicAuth`: the `Basic ` prefix (one space included)
/// matches in any case, the rest must be padded standard base64, and the
/// decoded bytes split at the first `:`. Anything else, extra spaces after
/// the scheme included, is `None`.
fn parse_basic_auth(header: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    const PREFIX: &str = "Basic ";
    let scheme = header.get(..PREFIX.len())?;
    if !scheme.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let decoded = GO_STD_ENCODING.decode(&header[PREFIX.len()..]).ok()?;
    let colon = decoded.iter().position(|&b| b == b':')?;
    let mut user = decoded;
    let pass = user.split_off(colon + 1);
    user.truncate(colon);
    Some((user, pass))
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

    fn basic(scheme: &str, user_pass: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(user_pass);
        format!("{scheme} {encoded}")
    }

    #[test]
    fn matches_the_scheme_in_any_case() {
        let creds = Credentials::new([("alice".to_owned(), "secret".to_owned())]);
        for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
            assert!(
                creds.is_authorized(Some(&basic(scheme, "alice:secret"))),
                "{scheme}"
            );
        }
        assert!(!creds.is_authorized(Some(&basic("Bearer", "alice:secret"))));
    }

    #[test]
    fn rejects_malformed_headers_as_go_does() {
        let creds = Credentials::new([("alice".to_owned(), "secret".to_owned())]);
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        for header in [
            // Go's prefix is exactly `Basic ` (one space).
            format!("Basic  {encoded}"),
            format!("Basic\t{encoded}"),
            format!("Basic{encoded}"),
            format!("Basic {encoded} "),
            "Basic".to_owned(),
            "Basic ".to_owned(),
            // Not base64.
            "Basic !!!!".to_owned(),
            // No `:` in the decoded value.
            basic("Basic", "alicesecret"),
        ] {
            assert!(!creds.is_authorized(Some(&header)), "{header:?}");
        }
    }

    #[test]
    fn splits_the_decoded_value_at_the_first_colon() {
        let creds = Credentials::new([
            ("alice".to_owned(), "pass:with:colons".to_owned()),
            ("bob".to_owned(), String::new()),
        ]);
        assert!(creds.is_authorized(Some(&basic("Basic", "alice:pass:with:colons"))));
        assert!(creds.is_authorized(Some(&basic("Basic", "bob:"))));
        assert!(!creds.is_authorized(Some(&basic("Basic", "bob"))));
        assert!(!creds.is_authorized(Some(&basic("Basic", "bob: "))));
    }

    #[test]
    fn accepts_non_canonical_trailing_bits_like_go() {
        // `YTo=` is "a:"; `YTp=` sets an unused bit in the last character,
        // which Go's StdEncoding ignores and the crate's STANDARD rejects.
        let creds = Credentials::new([("a".to_owned(), String::new())]);
        assert!(creds.is_authorized(Some("Basic YTo=")));
        assert!(creds.is_authorized(Some("Basic YTp=")));
        // Padding is still required, as in Go.
        assert!(!creds.is_authorized(Some("Basic YTo")));
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
    fn parse_pair_keeps_quotes_but_flags_them() {
        let (user, pass) = Credentials::parse_pair("'alice:secret'").unwrap();
        assert_eq!(user, "'alice");
        assert_eq!(pass, "secret'");
        assert!(is_quoted("'alice:secret'"));
        assert!(is_quoted("\"alice:secret\""));

        for unquoted in [
            "alice:secret",
            "alice:secret'",
            "'alice:secret\"",
            "alice:'secret'",
            "'",
        ] {
            assert!(!is_quoted(unquoted), "{unquoted}");
        }
    }

    #[test]
    fn parse_pair_rejects_missing_colon() {
        assert!(Credentials::parse_pair("no-colon-here").is_err());
    }
}
