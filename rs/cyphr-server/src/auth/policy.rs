//! What a login is granted: the permissions a service decides.
//!
//! SPEC 17.4 puts "authorized permissions" in the bearer token but names
//! none, so the names are the integrating service's own strings. A service
//! supplies a [`LoginPolicy`]; the login flow asks it once, after the
//! signature, key and lifecycle checks have passed, and signs the answer
//! into the token. A route then states its requirement with
//! [`require`](super::middleware::require).

use cyphr::PrincipalGenesis;

/// Decides the permissions a verified login is granted.
pub trait LoginPolicy: Send + Sync {
    /// The permissions to sign into the token for the principal `pg`
    /// logging in with `login_key`.
    fn perms(&self, pg: &PrincipalGenesis, login_key: &coz::Thumbprint) -> Vec<String>;
}

/// The policy a server runs when its service supplies none: a login is
/// granted no permissions. No Cyphr route requires one, so the token still
/// proves who logged in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPermissions;

impl LoginPolicy for NoPermissions {
    fn perms(&self, _pg: &PrincipalGenesis, _login_key: &coz::Thumbprint) -> Vec<String> {
        Vec::new()
    }
}
