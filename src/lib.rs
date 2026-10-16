#![doc = include_str!("../README.md")]
#![warn(missing_docs, missing_debug_implementations)]
#![deny(non_ascii_idents)]

mod client;

use std::{fmt, future::Future, time::SystemTime};

use certutils::PrivateKey;
use serde::{Deserialize, Serialize};

pub use client::{AcmeClient, AcmeClientBuilder};

/// An error from the ACME server, transport, cryptography, or challenge handler.
///
/// Non-success HTTP responses can be inspected by downcasting to [`AcmeProblem`].
/// Other errors retain their original concrete types. See the [error-handling
/// example](crate#limits-and-errors).
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A P-256 account signing key. Persist it before registering the account so a
/// failed or interrupted registration can be retried with the same identity.
///
/// Debug output redacts the key; PEM export must be treated as a secret.
///
/// # Examples
///
/// ```
/// use acme_client2::{AccountKey, Error};
///
/// let key = AccountKey::generate()?;
/// let pem = key.to_pkcs8_pem()?;
/// let restored = AccountKey::from_pkcs8_pem(&pem)?;
/// assert_eq!(restored.to_pkcs8_pem()?, pem);
/// # Ok::<(), Error>(())
/// ```
pub struct AccountKey {
    pub(crate) inner: PrivateKey,
}

impl AccountKey {
    /// Generate a new account signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if cryptographic key generation fails.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self {
            inner: PrivateKey::generate()?,
        })
    }

    /// Restore a P-256 account signing key from PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM cannot be decoded or the key is unsupported.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: PrivateKey::from_pkcs8_pem(pem)?,
        })
    }

    /// Export the private key. Store this securely; it controls the CA account.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic backend cannot encode the key.
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        Ok(self.inner.to_pkcs8_pem()?)
    }
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountKey")
            .field("private_key", &"[redacted]")
            .finish()
    }
}

/// Options sent to the CA when registering an account.
///
/// # Examples
///
/// ```
/// use acme_client2::AccountOptions;
///
/// let options = AccountOptions::new()
///     .contact("mailto:admin@example.com")
///     .agree_to_terms_of_service();
/// assert_eq!(options.contacts(), ["mailto:admin@example.com"]);
/// assert!(options.terms_of_service_agreed());
/// ```
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct AccountOptions {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contact: Vec<String>,
    terms_of_service_agreed: bool,
}

impl AccountOptions {
    /// Options with no contacts and without agreement to the CA's terms.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a contact URI, for example `mailto:admin@example.com`.
    pub fn contact(mut self, uri: impl Into<String>) -> Self {
        self.contact.push(uri.into());
        self
    }

    /// Explicitly agree to the CA's terms of service. Review the terms from
    /// [`AcmeClient::terms_of_service_url`] first.
    pub fn agree_to_terms_of_service(mut self) -> Self {
        self.terms_of_service_agreed = true;
        self
    }

    /// The contact URIs, in the order they were added.
    #[must_use]
    pub fn contacts(&self) -> &[String] {
        &self.contact
    }

    /// Whether the CA's terms of service are agreed to; defaults to false.
    #[must_use]
    pub fn terms_of_service_agreed(&self) -> bool {
        self.terms_of_service_agreed
    }
}

/// Serializable account state. Treat the entire value as a secret.
///
/// The directory URL binds the account to its CA environment, preventing
/// accidental reuse of staging credentials with a production directory.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountCredentials {
    /// The exact directory URL used to create this account.
    pub directory_url: String,
    /// The account resource URL assigned by the CA.
    pub account_url: String,
    /// The secret account signing key, encoded as PKCS#8 PEM.
    pub private_key_pem: String,
}

impl fmt::Debug for AccountCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredentials")
            .field("directory_url", &self.directory_url)
            .field("account_url", &self.account_url)
            .field("private_key_pem", &"[redacted]")
            .finish()
    }
}

/// A registered account, restored or created through an [`AcmeClient`].
#[derive(Debug)]
pub struct Account {
    pub(crate) key: AccountKey,
    pub(crate) url: String,
    pub(crate) directory_url: String,
}

impl Account {
    /// The account resource URL assigned by the CA.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Export the state needed by [`AcmeClient::restore_account`].
    ///
    /// # Errors
    ///
    /// Returns an error if the account private key cannot be encoded as PEM.
    pub fn credentials(&self) -> Result<AccountCredentials, Error> {
        Ok(AccountCredentials {
            directory_url: self.directory_url.clone(),
            account_url: self.url.clone(),
            private_key_pem: self.key.to_pkcs8_pem()?,
        })
    }
}

/// A challenge method implemented by this version of the client.
///
/// Additional methods can be added in future versions. Handlers should reject
/// methods they do not recognize in [`ChallengeHandler::supports`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ChallengeType {
    /// Serve a key authorization over HTTP on the identifier's port 80.
    Http01,
}

impl ChallengeType {
    /// The challenge type used by the ACME protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
        }
    }

    pub(crate) fn from_acme(value: &str) -> Option<Self> {
        match value {
            "http-01" => Some(Self::Http01),
            _ => None,
        }
    }
}

impl fmt::Display for ChallengeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ChallengeType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Method-specific material to publish before the CA validates a challenge.
///
/// Future methods will have their own variants and payloads, without changing
/// the [`ChallengeHandler`] lifecycle or the certificate issuance API.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Challenge {
    /// The response to serve for an HTTP-01 challenge.
    Http01(Http01Challenge),
}

impl Challenge {
    /// The method needed to publish this challenge.
    #[must_use]
    pub fn challenge_type(&self) -> ChallengeType {
        match self {
            Self::Http01(_) => ChallengeType::Http01,
        }
    }
}

impl From<Http01Challenge> for Challenge {
    fn from(challenge: Http01Challenge) -> Self {
        Self::Http01(challenge)
    }
}

/// Application-owned publication and removal for supported challenge methods.
///
/// The client selects the first CA-offered challenge implemented by both the
/// library and the handler. Unknown or unsupported methods are skipped; if none
/// remain, issuance fails before publication or acknowledgement.
///
/// `present` must return only after the challenge is available to the CA.
/// `cleanup` must be idempotent: it is also called when `present` fails or times
/// out after partially publishing a challenge. The same challenge data is used
/// for publication and cleanup.
///
/// Issuance attempts cleanup on success, error, and its own timeout. Dropping
/// the issuance future or terminating the process cannot run async cleanup,
/// so handlers should also expire stored challenges.
///
/// Implement this trait directly for method-aware dispatch, or implement
/// [`Http01Handler`] for the HTTP-01-only convenience adapter, but not both.
///
/// This trait uses static dispatch and is not dyn-compatible. Use a concrete
/// handler (which may dispatch to multiple backends internally), not a trait
/// object. See the [challenge integration examples](crate#publish-http-01-challenges).
pub trait ChallengeHandler: Sync {
    /// Whether this handler can publish and clean up the given method.
    /// Return false for unrecognized methods.
    fn supports(&self, challenge_type: ChallengeType) -> bool;

    /// Publish the supplied material and wait until it is available to the CA.
    ///
    /// # Errors
    ///
    /// Return an error if publication fails or the method is unsupported. Cleanup
    /// will still be attempted, so partial publication must be removable.
    fn present(&self, challenge: &Challenge) -> impl Future<Output = Result<(), Error>> + Send;

    /// Remove previously published material; repeated removal should succeed.
    ///
    /// # Errors
    ///
    /// Return an error if the published material cannot be removed. An issuance
    /// error takes precedence over this error when both operations fail.
    fn cleanup(&self, challenge: &Challenge) -> impl Future<Output = Result<(), Error>> + Send;
}

/// An HTTP-01 response to publish before the CA is asked to validate it.
#[derive(Clone, Debug)]
pub struct Http01Challenge {
    /// The DNS identifier being validated.
    pub domain: String,
    /// The exact URL-safe token supplied by the CA.
    pub token: String,
    /// Exact response body, without JSON encoding or additional quoting.
    pub key_authorization: String,
    /// Suggested storage expiry, matching the issuance deadline.
    pub expires_at: SystemTime,
}

impl Http01Challenge {
    /// The HTTP path the CA will request on port 80 of [`Self::domain`].
    #[must_use]
    pub fn path(&self) -> String {
        format!("/.well-known/acme-challenge/{}", self.token)
    }
}

/// HTTP-01-only convenience interface for challenge publication and removal.
///
/// Implementors automatically implement [`ChallengeHandler`], so existing
/// HTTP-01 handlers can be passed directly to [`AcmeClient::issue_certificate`].
///
/// `present` must return only after the response is publicly available. Serve
/// the exact path from [`Http01Challenge::path`] with the key authorization as
/// a `text/plain` body. `cleanup` should be idempotent: it is also called when
/// `present` fails or times out after partially publishing a challenge.
///
/// Issuance always attempts cleanup on success, error, and its own timeout.
/// Dropping the issuance future or terminating the process cannot run async
/// cleanup, so handlers should also expire stored challenges.
///
/// Like [`ChallengeHandler`], this trait uses static dispatch and is not
/// dyn-compatible. See the [HTTP-01 example](crate#publish-http-01-challenges).
pub trait Http01Handler: Sync {
    /// Make the HTTP-01 response available on the challenge's exact path.
    ///
    /// # Errors
    ///
    /// Return an error if publication fails. Cleanup is attempted even when
    /// publication only partially succeeds.
    fn present(
        &self,
        challenge: &Http01Challenge,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Remove the HTTP-01 response, succeeding if it is already absent.
    ///
    /// # Errors
    ///
    /// Return an error if removal fails. An issuance error takes precedence over
    /// a cleanup error when both operations fail.
    fn cleanup(
        &self,
        challenge: &Http01Challenge,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

impl<Handler: Http01Handler + ?Sized> ChallengeHandler for Handler {
    fn supports(&self, challenge_type: ChallengeType) -> bool {
        matches!(challenge_type, ChallengeType::Http01)
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), Error> {
        match challenge {
            Challenge::Http01(challenge) => Http01Handler::present(self, challenge).await,
        }
    }

    async fn cleanup(&self, challenge: &Challenge) -> Result<(), Error> {
        match challenge {
            Challenge::Http01(challenge) => Http01Handler::cleanup(self, challenge).await,
        }
    }
}

/// A validated PEM certificate chain and its matching PKCS#8 private key.
///
/// No files are written and no TLS listener is reconfigured by the library.
/// Debug output redacts the private key and omits the potentially large chain.
pub struct IssuedCertificate {
    /// The PEM certificate chain, with the leaf first.
    pub certificate_pem: String,
    /// The matching secret private key, encoded as PKCS#8 PEM.
    pub private_key_pem: String,
    /// The leaf certificate's expiry time, for renewal scheduling.
    pub not_after: SystemTime,
}

impl fmt::Debug for IssuedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCertificate")
            .field("private_key_pem", &"[redacted]")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// A non-success HTTP response from an ACME endpoint.
///
/// Available by downcasting [`Error`]. `problem_type` and `detail` are populated
/// when the response contains an ACME problem document.
#[derive(Debug)]
pub struct AcmeProblem {
    /// The HTTP response status code.
    pub status: u16,
    /// The problem type URI, if a problem document was returned.
    pub problem_type: Option<String>,
    /// The server's explanation, if provided in the problem document.
    pub detail: Option<String>,
    /// The complete response body, decoded with replacement for invalid UTF-8.
    pub body: String,
}

impl fmt::Display for AcmeProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_CHARS: usize = 512;
        let message = match (&self.problem_type, &self.detail) {
            (Some(kind), Some(detail)) => format!("{kind}: {detail}"),
            (Some(text), None) | (None, Some(text)) => text.clone(),
            (None, None) => self.body.clone(),
        };
        match message.char_indices().nth(MAX_CHARS) {
            Some((end, _)) => write!(
                formatter,
                "ACME server returned {}: {}...",
                self.status,
                &message[..end]
            ),
            None => write!(formatter, "ACME server returned {}: {message}", self.status),
        }
    }
}

impl std::error::Error for AcmeProblem {}
