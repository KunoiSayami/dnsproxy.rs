//! URL path routing for the DoH/DoH3 listeners: when configured, only
//! requests for one of a set of exact paths are served, and every other path
//! gets a bare 404, mirroring Go's `doh-routes` (`proxy/route.go`, registered
//! on an `http.ServeMux`). A secret path (e.g. `/<random>/dns-query`) then
//! works as access control for clients that can't send Basic Auth.

/// The set of URL paths the DoH/DoH3 listeners answer on. Empty means any
/// path, matching Go's default routes (`/`, which `ServeMux` treats as a
/// catch-all, plus `/dns-query`).
#[derive(Default)]
pub struct DohRoutes {
    paths: Vec<String>,
}

impl DohRoutes {
    /// Builds a route set from paths already checked by [`Self::parse_path`],
    /// e.g. from repeated `--doh-path` flags or lines of a `--doh-path-file`.
    pub fn new(paths: impl IntoIterator<Item = String>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

    /// Whether any paths are configured. When none are, every path is
    /// served.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// The number of configured paths, for logging without revealing them.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether a request for `path` (the request URI's path, without the
    /// query string) should be served. Matching is exact and on the raw,
    /// still percent-encoded path: unlike a Go `ServeMux`, no path cleaning
    /// or redirect happens, so `/secret//dns-query` or a trailing `/` is
    /// simply a 404, as is a pattern ending in `/` for anything below it.
    ///
    /// Every listener checks this before authentication and before reading
    /// the body, so a wrong path is indistinguishable from a server with no
    /// DoH endpoint there.
    pub fn allows(&self, path: &str) -> bool {
        self.paths.is_empty() || self.paths.iter().any(|p| p == path)
    }

    /// Validates one path, as given on the `--doh-path` flag or one line of
    /// `--doh-path-file`. It must be an absolute path with no query string,
    /// fragment, or whitespace. Errors don't echo the path, since it's
    /// usually a secret.
    pub fn parse_path(s: &str) -> Result<String, String> {
        if !s.starts_with('/') {
            return Err("invalid DoH path: must start with \"/\"".to_owned());
        }
        if s.contains(['?', '#']) || s.chars().any(char::is_whitespace) {
            return Err(
                "invalid DoH path: must not contain \"?\", \"#\", or whitespace".to_owned(),
            );
        }
        Ok(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_allows_every_path() {
        let routes = DohRoutes::default();
        assert!(routes.allows("/"));
        assert!(routes.allows("/dns-query"));
        assert!(routes.allows("/anything/else"));
    }

    #[test]
    fn configured_paths_match_exactly() {
        let routes = DohRoutes::new(["/s3cr3t/dns-query".to_owned(), "/other".to_owned()]);
        assert!(routes.allows("/s3cr3t/dns-query"));
        assert!(routes.allows("/other"));
        for path in [
            "/",
            "/dns-query",
            "/s3cr3t",
            "/s3cr3t/",
            "/s3cr3t/dns-query/",
            "/s3cr3t/dns-query/x",
            "/s3cr3t//dns-query",
            "/S3CR3T/dns-query",
        ] {
            assert!(!routes.allows(path), "{path:?} should be rejected");
        }
    }

    #[test]
    fn parse_path_rejects_malformed_paths_without_echoing_them() {
        assert_eq!(DohRoutes::parse_path("/a/b").unwrap(), "/a/b");
        for bad in ["s3cr3t", "/s3cr3t?x=1", "/s3cr3t#x", "/s3 cr3t", ""] {
            let err = DohRoutes::parse_path(bad).unwrap_err();
            assert!(bad.is_empty() || !err.contains(bad), "{err}");
        }
    }
}
