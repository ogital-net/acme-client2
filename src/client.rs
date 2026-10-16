use std::{
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

use base64_simd::URL_SAFE_NO_PAD;
use bytes::Bytes;
use certutils::{Certificate, CertificateSigningRequest, DnsName, PrivateKey, SubjectAltName};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{HeaderMap, Method, Request, StatusCode, Uri, header};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use jose4rs::{
    jws::{AlgorithmIdentifier, JsonWebSignature},
    jwx::JsonWebStructure,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio_aws_lc::{ClientConfig, TlsConnector, hyper::HttpsConnector};

use crate::{
    Account, AccountCredentials, AccountKey, AccountOptions, AcmeProblem,
    Challenge as PresentedChallenge, ChallengeHandler, ChallengeType, Error, Http01Challenge,
    IssuedCertificate,
};

type HyperClient = Client<HttpsConnector, Full<Bytes>>;

#[derive(Clone, Debug)]
struct ClientOptions {
    accept_invalid_certs: bool,
    allow_cross_origin_urls: bool,
    request_timeout: Duration,
    issuance_timeout: Duration,
    poll_interval: Duration,
}

/// Configures transport and polling limits, then fetches the ACME directory.
///
/// Created by [`AcmeClient::builder`]. Defaults: 30 second requests, 10 minute
/// issuance, 2 second minimum poll interval, and TLS verification enabled.
#[derive(Clone, Debug)]
#[must_use]
pub struct AcmeClientBuilder {
    directory_url: String,
    options: ClientOptions,
}

impl AcmeClientBuilder {
    /// Timeout for each HTTP request, including reading its response body.
    /// Also bounds each challenge cleanup call. Must be positive.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.options.request_timeout = timeout;
        self
    }

    /// Overall issuance timeout, excluding challenge cleanup. Authorization and
    /// order polling continue until this deadline. Must be positive.
    pub fn issuance_timeout(mut self, timeout: Duration) -> Self {
        self.options.issuance_timeout = timeout;
        self
    }

    /// Minimum delay between authorization and order polls. A longer
    /// `Retry-After` from the CA takes precedence. Zero is permitted.
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.options.poll_interval = interval;
        self
    }

    /// Disable server certificate verification. Use only with a local test CA;
    /// this permits interception of account and certificate traffic.
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.options.accept_invalid_certs = true;
        self
    }

    /// Permit signed requests to URLs on a different scheme, host, or port than
    /// the directory URL. Use only for a CA known to split its ACME endpoints
    /// across hosts; HTTPS and certificate verification still apply.
    pub fn allow_cross_origin_urls(mut self) -> Self {
        self.options.allow_cross_origin_urls = true;
        self
    }

    /// Fetch the ACME directory and create the client.
    ///
    /// # Errors
    ///
    /// Returns an error if a timeout is zero, or if TLS setup, URL parsing, the
    /// HTTP request, or directory decoding fails. Unless
    /// [`Self::allow_cross_origin_urls`] is set, directory endpoints must share
    /// the directory URL's origin. HTTP responses are limited to 1 MiB.
    ///
    /// # Panics
    ///
    /// May panic when polled outside a Tokio runtime with I/O and time enabled.
    pub async fn build(self) -> Result<AcmeClient, Error> {
        let Self {
            directory_url,
            options,
        } = self;
        if options.request_timeout.is_zero() || options.issuance_timeout.is_zero() {
            return Err(invalid_data("ACME timeouts must be positive"));
        }
        let origin = (!options.allow_cross_origin_urls)
            .then(|| Origin::parse(&directory_url))
            .transpose()?;
        let mut config = ClientConfig::builder()
            .alpn_protocols(&[b"http/1.1"])
            .disable_ktls();
        if options.accept_invalid_certs {
            config = config.dangerous_disable_verification();
        } else {
            config = config.with_system_root_certs();
        }
        let tls = TlsConnector::new(Arc::new(config.build()?));
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.enforce_http(false);
        http.set_connect_timeout(Some(options.request_timeout));
        let connector = HttpsConnector::with_http_connector(http, tls);
        let inner = Client::builder(TokioExecutor::new()).build(connector);
        let directory: Directory =
            request(&inner, &options, Method::GET, &directory_url, Bytes::new())
                .await?
                .checked()?
                .json()?;
        for url in [
            &directory.new_nonce,
            &directory.new_account,
            &directory.new_order,
        ] {
            check_origin(origin.as_ref(), url)?;
        }
        Ok(AcmeClient {
            inner,
            directory_url,
            origin,
            directory,
            options,
            nonce: Arc::default(),
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn parse(url: &str) -> Result<Self, Error> {
        let uri: Uri = url.parse()?;
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| invalid_data("ACME URL must be absolute"))?
            .to_ascii_lowercase();
        let host = uri
            .host()
            .ok_or_else(|| invalid_data("ACME URL must have a host"))?
            .to_ascii_lowercase();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "http" { 80 } else { 443 });
        Ok(Self { scheme, host, port })
    }
}

/// Keeps signed account requests on the CA that served the directory.
fn check_origin(origin: Option<&Origin>, url: &str) -> Result<(), Error> {
    if let Some(origin) = origin
        && Origin::parse(url)? != *origin
    {
        return Err(invalid_data(format!(
            "ACME URL {url} is on a different origin than the directory"
        )));
    }
    Ok(())
}

/// An ACME directory and a reusable HTTP connection pool.
#[derive(Clone)]
pub struct AcmeClient {
    inner: HyperClient,
    directory_url: String,
    origin: Option<Origin>,
    directory: Directory,
    options: ClientOptions,
    nonce: Arc<Mutex<Option<String>>>,
}

impl fmt::Debug for AcmeClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeClient")
            .field("directory_url", &self.directory_url)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

struct AcmeResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl AcmeResponse {
    fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    fn checked(self) -> Result<Self, Error> {
        if self.status.is_success() {
            return Ok(self);
        }
        let problem = serde_json::from_slice::<Value>(&self.body).unwrap_or_default();
        Err(AcmeProblem {
            status: self.status.as_u16(),
            problem_type: problem["type"].as_str().map(str::to_owned),
            detail: problem["detail"].as_str().map(str::to_owned),
            body: String::from_utf8_lossy(&self.body).into_owned(),
        }
        .into())
    }

    fn location(&self) -> Result<String, Error> {
        Ok(self
            .headers
            .get(header::LOCATION)
            .ok_or_else(|| invalid_data("ACME response has no Location header"))?
            .to_str()?
            .to_owned())
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    #[serde(default)]
    meta: DirectoryMeta,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryMeta {
    terms_of_service: Option<String>,
}

#[derive(Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct Authorization {
    status: String,
    identifier: Identifier,
    #[serde(default)]
    wildcard: bool,
    #[serde(default)]
    challenges: Vec<Challenge>,
}

#[derive(Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: Option<String>,
    error: Option<Problem>,
}

#[derive(Deserialize)]
struct Problem {
    #[serde(rename = "type")]
    kind: Option<String>,
    detail: Option<String>,
}

#[derive(Deserialize)]
struct AccountResource {
    status: String,
}

impl AcmeClient {
    /// Fetch an ACME directory using secure default transport settings.
    ///
    /// Use [`Self::builder`] to change timeouts or polling. See the
    /// [issuance example](crate#issue-or-renew).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`AcmeClientBuilder::build`].
    ///
    /// # Panics
    ///
    /// May panic when polled outside a Tokio runtime with I/O and time enabled.
    pub async fn new(directory_url: impl Into<String>) -> Result<Self, Error> {
        Self::builder(directory_url).build().await
    }

    /// Configure a client for the given ACME directory URL.
    pub fn builder(directory_url: impl Into<String>) -> AcmeClientBuilder {
        AcmeClientBuilder {
            directory_url: directory_url.into(),
            options: ClientOptions {
                accept_invalid_certs: false,
                allow_cross_origin_urls: false,
                request_timeout: Duration::from_secs(30),
                issuance_timeout: Duration::from_secs(10 * 60),
                poll_interval: Duration::from_secs(2),
            },
        }
    }

    /// The CA's terms URL, when advertised by the directory.
    #[must_use]
    pub fn terms_of_service_url(&self) -> Option<&str> {
        self.directory.meta.terms_of_service.as_deref()
    }

    /// Register an account, or recover an existing account using the same key.
    /// Persist the key before calling, then persist [`Account::credentials`].
    /// See the [registration example](crate#register-and-persist-an-account).
    ///
    /// # Errors
    ///
    /// Returns an error if signing, serialization, or transport fails, the CA
    /// rejects registration, the account is not `valid`, or the response has no
    /// usable account Location.
    /// Retry with the previously persisted key after an ambiguous failure.
    ///
    /// # Panics
    ///
    /// May panic when polled outside a Tokio runtime with I/O and time enabled.
    pub async fn create_account(
        &self,
        key: AccountKey,
        options: AccountOptions,
    ) -> Result<Account, Error> {
        let response = self
            .signed_post(
                &key.inner,
                None,
                &self.directory.new_account,
                &serde_json::to_vec(&options)?,
            )
            .await?;
        let url = response.location()?;
        let resource: AccountResource = response.json()?;
        if resource.status != "valid" {
            return Err(invalid_data(format!("ACME account is {}", resource.status)));
        }
        Ok(Account {
            key,
            url,
            directory_url: self.directory_url.clone(),
        })
    }

    /// Restore persisted credentials without making a network request.
    /// The credentials must belong to this exact directory URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory URL differs or the private key cannot
    /// be decoded. The account's existence is checked by the CA on later requests.
    pub fn restore_account(&self, credentials: AccountCredentials) -> Result<Account, Error> {
        if credentials.directory_url != self.directory_url {
            return Err(invalid_data(
                "ACME account belongs to a different directory",
            ));
        }
        Ok(Account {
            key: AccountKey::from_pkcs8_pem(&credentials.private_key_pem)?,
            url: credentials.account_url,
            directory_url: credentials.directory_url,
        })
    }

    /// Issue a certificate for one DNS name using a supported challenge method.
    ///
    /// Currently only HTTP-01 is implemented. The handler advertises supported
    /// methods through [`ChallengeHandler::supports`]; existing
    /// [`crate::Http01Handler`] implementations are adapted automatically.
    ///
    /// The returned leaf is checked for its DNS name, public key, and expiry, and
    /// each certificate in the chain must be signed by the next one. `notBefore`
    /// is not checked, so modest clock skew does not discard a fresh certificate.
    /// A fresh certificate key is generated for every order. Account keys are
    /// never reused as certificate keys. Wildcards and IP addresses are not
    /// supported.
    ///
    /// Polling continues until the issuance timeout, using the larger of the
    /// configured poll interval and the CA's `Retry-After` (in seconds). If issuance
    /// fails after the order is finalized, the CA may have issued a certificate
    /// whose private key is discarded; size the issuance timeout generously.
    ///
    /// Cleanup is attempted for every presented challenge, including after
    /// timeout or a partially failed `present`. An issuance error takes
    /// precedence over a cleanup error; otherwise a cleanup error is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, wildcard, or IP address names, accounts from
    /// another directory, unsupported challenges, failed authorization or
    /// finalization, CA URLs on a different origin than the directory, invalid
    /// certificates, cryptographic or HTTP failures, and timeouts. Handler
    /// publication and cleanup errors are also returned.
    ///
    /// # Panics
    ///
    /// May panic when polled outside a Tokio runtime with I/O and time enabled.
    /// Panics in caller-provided handlers are not caught and can prevent cleanup.
    pub async fn issue_certificate(
        &self,
        account: &Account,
        domain: &str,
        handler: &impl ChallengeHandler,
    ) -> Result<IssuedCertificate, Error> {
        if account.directory_url != self.directory_url {
            return Err(invalid_data(
                "ACME account belongs to a different directory",
            ));
        }
        if domain.split('.').any(|label| label == "*") {
            return Err(invalid_data(
                "HTTP-01 does not support wildcard certificates",
            ));
        }
        if domain.parse::<IpAddr>().is_ok() {
            return Err(invalid_data("IP address identifiers are not supported"));
        }
        let dns_name = DnsName::new(domain)?;
        let mut presented = Vec::new();
        let expires_at = SystemTime::now()
            .checked_add(self.options.issuance_timeout)
            .ok_or_else(|| invalid_data("ACME issuance timeout is too large"))?;
        let result = tokio::time::timeout(
            self.options.issuance_timeout,
            self.issue_inner(account, dns_name, handler, expires_at, &mut presented),
        )
        .await
        .map_err(|_| invalid_data("ACME certificate issuance timed out"))
        .and_then(|result| result);
        let mut cleanup_error = None;
        for challenge in &presented {
            let cleanup =
                tokio::time::timeout(self.options.request_timeout, handler.cleanup(challenge))
                    .await
                    .map_err(|_| invalid_data("ACME challenge cleanup timed out"))
                    .and_then(|result| result);
            if let Err(error) = cleanup {
                cleanup_error.get_or_insert(error);
            }
        }
        let certificate = result?;
        if let Some(error) = cleanup_error {
            return Err(error);
        }
        Ok(certificate)
    }

    async fn issue_inner(
        &self,
        account: &Account,
        dns_name: DnsName,
        handler: &impl ChallengeHandler,
        expires_at: SystemTime,
        presented: &mut Vec<PresentedChallenge>,
    ) -> Result<IssuedCertificate, Error> {
        let response = self
            .account_post(
                account,
                &self.directory.new_order,
                &serde_json::to_vec(&json!({
                    "identifiers": [{ "type": "dns", "value": dns_name.as_str() }]
                }))?,
            )
            .await?;
        let order_url = response.location()?;
        let order: Order = response.json()?;
        if !matches!(order.status.as_str(), "pending" | "ready") {
            return Err(invalid_data(format!(
                "unexpected new ACME order status: {}",
                order.status
            )));
        }
        for authorization_url in &order.authorizations {
            self.complete_authorization(
                account,
                dns_name.as_str(),
                authorization_url,
                handler,
                expires_at,
                presented,
            )
            .await?;
        }
        let ready = self.wait_for_order(account, &order_url, "ready").await?;
        let certificate_key = PrivateKey::generate()?;
        let csr = CertificateSigningRequest::builder()
            .dns_name(dns_name.clone())
            .build(&certificate_key)?;
        self.account_post(
            account,
            &ready.finalize,
            &serde_json::to_vec(&json!({
                "csr": URL_SAFE_NO_PAD.encode_to_string(csr.as_der())
            }))?,
        )
        .await?;
        let order = self.wait_for_order(account, &order_url, "valid").await?;
        let certificate_url = order
            .certificate
            .ok_or_else(|| invalid_data("valid ACME order has no certificate URL"))?;
        let response = self.account_post(account, &certificate_url, b"").await?;
        let certificate_pem = String::from_utf8(response.body.to_vec())?;
        let chain = Certificate::from_pem_chain(&certificate_pem)?;
        let leaf = chain
            .first()
            .ok_or_else(|| invalid_data("ACME server returned an empty certificate chain"))?;
        if !leaf.subject_alt_names()?.iter().any(|name| {
            matches!(name, SubjectAltName::Dns(name) if name.as_str().eq_ignore_ascii_case(dns_name.as_str()))
        }) {
            return Err(invalid_data("issued certificate does not contain the requested DNS name"));
        }
        if leaf.public_key()? != certificate_key.public_key()? {
            return Err(invalid_data(
                "issued certificate does not match the private key",
            ));
        }
        for pair in chain.windows(2) {
            if pair[0].issuer()? != pair[1].subject()?
                || pair[0].verify_signature(&pair[1].public_key()?).is_err()
            {
                return Err(invalid_data(
                    "ACME certificate chain is not correctly ordered or signed",
                ));
            }
        }
        let validity = leaf.validity()?;
        if validity.not_after() <= SystemTime::now() {
            return Err(invalid_data("issued certificate has expired"));
        }
        Ok(IssuedCertificate {
            certificate_pem,
            private_key_pem: certificate_key.to_pkcs8_pem()?,
            not_after: validity.not_after(),
        })
    }

    async fn complete_authorization(
        &self,
        account: &Account,
        domain: &str,
        authorization_url: &str,
        handler: &impl ChallengeHandler,
        expires_at: SystemTime,
        presented: &mut Vec<PresentedChallenge>,
    ) -> Result<(), Error> {
        let authorization: Authorization = self
            .account_post(account, authorization_url, b"")
            .await?
            .json()?;
        if authorization.identifier.kind != "dns"
            || !authorization.identifier.value.eq_ignore_ascii_case(domain)
            || authorization.wildcard
        {
            return Err(invalid_data(
                "ACME authorization does not match the requested DNS name",
            ));
        }
        match authorization.status.as_str() {
            "valid" => return Ok(()),
            "pending" => {}
            _ => return Err(authorization_error(&authorization)),
        }
        let (challenge, challenge_type) = authorization
            .challenges
            .into_iter()
            .find_map(|challenge| {
                let challenge_type = ChallengeType::from_acme(&challenge.kind)?;
                handler
                    .supports(challenge_type)
                    .then_some((challenge, challenge_type))
            })
            .ok_or_else(|| invalid_data("ACME authorization has no supported challenge"))?;
        let token = challenge
            .token
            .ok_or_else(|| invalid_data("ACME challenge has no token"))?;
        if !valid_token(&token) {
            return Err(invalid_data(
                "ACME challenge token contains invalid characters",
            ));
        }
        let thumbprint = account.key.inner.to_jose_jwk()?.thumbprint()?;
        let publication = match challenge_type {
            ChallengeType::Http01 => PresentedChallenge::Http01(Http01Challenge {
                domain: domain.to_owned(),
                key_authorization: format!("{token}.{thumbprint}"),
                token,
                expires_at,
            }),
        };
        presented.push(publication.clone());
        handler.present(&publication).await?;
        let response = self.account_post(account, &challenge.url, b"{}").await?;
        let mut delay = self.poll_delay(&response);
        loop {
            tokio::time::sleep(delay).await;
            let response = self.account_post(account, authorization_url, b"").await?;
            delay = self.poll_delay(&response);
            let authorization: Authorization = response.json()?;
            match authorization.status.as_str() {
                "valid" => return Ok(()),
                "pending" => {}
                _ => return Err(authorization_error(&authorization)),
            }
        }
    }

    async fn wait_for_order(
        &self,
        account: &Account,
        order_url: &str,
        desired_status: &str,
    ) -> Result<Order, Error> {
        loop {
            let response = self.account_post(account, order_url, b"").await?;
            let order: Order = response.json()?;
            if order.status == desired_status {
                return Ok(order);
            }
            let waiting = match desired_status {
                "ready" => order.status == "pending",
                "valid" => matches!(order.status.as_str(), "ready" | "processing"),
                _ => false,
            };
            if !waiting {
                return Err(invalid_data(format!(
                    "unexpected ACME order status: {}",
                    order.status
                )));
            }
            tokio::time::sleep(self.poll_delay(&response)).await;
        }
    }

    fn poll_delay(&self, response: &AcmeResponse) -> Duration {
        let retry_after = response
            .headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok())
            .map(Duration::from_secs)
            .unwrap_or_default();
        retry_after.max(self.options.poll_interval)
    }

    async fn account_post(
        &self,
        account: &Account,
        url: &str,
        payload: &[u8],
    ) -> Result<AcmeResponse, Error> {
        self.signed_post(&account.key.inner, Some(&account.url), url, payload)
            .await
    }

    async fn signed_post(
        &self,
        key: &PrivateKey,
        account_url: Option<&str>,
        url: &str,
        payload: &[u8],
    ) -> Result<AcmeResponse, Error> {
        check_origin(self.origin.as_ref(), url)?;
        for attempt in 0..3 {
            let cached = self
                .nonce
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let nonce = if let Some(nonce) = cached {
                nonce
            } else {
                let response = request(
                    &self.inner,
                    &self.options,
                    Method::HEAD,
                    &self.directory.new_nonce,
                    Bytes::new(),
                )
                .await?
                .checked()?;
                response
                    .headers
                    .get("replay-nonce")
                    .ok_or_else(|| invalid_data("ACME nonce response has no Replay-Nonce header"))?
                    .to_str()?
                    .to_owned()
            };
            let body = signed_request(key, account_url, &nonce, url, payload)?;
            let response =
                request(&self.inner, &self.options, Method::POST, url, body.into()).await?;
            if let Some(nonce) = response
                .headers
                .get("replay-nonce")
                .and_then(|nonce| nonce.to_str().ok())
            {
                *self.nonce.lock().unwrap_or_else(PoisonError::into_inner) = Some(nonce.to_owned());
            }
            if response.status.is_success() {
                return Ok(response);
            }
            let is_bad_nonce = serde_json::from_slice::<Value>(&response.body)
                .is_ok_and(|problem| problem["type"] == "urn:ietf:params:acme:error:badNonce");
            if is_bad_nonce && attempt < 2 {
                continue;
            }
            return response.checked();
        }
        unreachable!("ACME nonce retries either return or fail")
    }
}

fn authorization_error(authorization: &Authorization) -> Error {
    let reason = authorization
        .challenges
        .iter()
        .find_map(|challenge| challenge.error.as_ref())
        .and_then(|problem| match (&problem.kind, &problem.detail) {
            (Some(kind), Some(detail)) => Some(format!(": {kind}: {detail}")),
            (Some(text), None) | (None, Some(text)) => Some(format!(": {text}")),
            (None, None) => None,
        })
        .unwrap_or_default();
    invalid_data(format!(
        "ACME authorization is {}{reason}",
        authorization.status
    ))
}

async fn request(
    client: &HyperClient,
    options: &ClientOptions,
    method: Method,
    url: &str,
    body: Bytes,
) -> Result<AcmeResponse, Error> {
    let is_post = method == Method::POST;
    let mut request = Request::builder().method(method).uri(url).header(
        header::USER_AGENT,
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
    );
    if is_post {
        request = request.header(header::CONTENT_TYPE, "application/jose+json");
    }
    let request = request.body(Full::new(body))?;
    tokio::time::timeout(options.request_timeout, async {
        let response = client.request(request).await?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, 1024 * 1024).collect().await?.to_bytes();
        Ok(AcmeResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    })
    .await
    .map_err(|_| invalid_data("ACME HTTP request timed out"))?
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invalid_data(message: impl Into<String>) -> Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn signed_request(
    key: &PrivateKey,
    account_url: Option<&str>,
    nonce: &str,
    url: &str,
    payload: &[u8],
) -> Result<String, Error> {
    let jwk = key.to_jose_jwk()?;
    let mut jws = JsonWebSignature::new();
    jws.set_algorithm(AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256);
    jws.set_header_name("nonce", nonce);
    jws.set_header_name("url", url);
    match account_url {
        Some(account_url) => jws.set_key_id_header_value(account_url),
        None => jws.set_jwk_header(&jwk),
    }
    jws.set_payload(payload);
    Ok(jws.flattened_json_serialization(&jwk)?)
}

#[cfg(test)]
mod tests {
    use base64_simd::URL_SAFE_NO_PAD;
    use serde_json::Value;

    use super::*;

    fn decode_part(request: &Value, name: &str) -> Value {
        let encoded = request[name].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode_to_vec(encoded.as_bytes()).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    #[test]
    fn new_account_request_embeds_public_jwk() {
        let key = PrivateKey::generate().unwrap();
        let request: Value = serde_json::from_str(
            &signed_request(
                &key,
                None,
                "nonce-value",
                "https://ca.example/new-account",
                br#"{"termsOfServiceAgreed":true}"#,
            )
            .unwrap(),
        )
        .unwrap();

        let protected = decode_part(&request, "protected");
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce-value");
        assert_eq!(protected["url"], "https://ca.example/new-account");
        assert_eq!(protected["jwk"]["kty"], "EC");
        assert!(protected.get("kid").is_none());
        assert!(protected["jwk"].get("d").is_none());
        assert_eq!(
            decode_part(&request, "payload")["termsOfServiceAgreed"],
            true
        );
    }

    #[test]
    fn account_request_uses_kid_and_supports_post_as_get() {
        let key = PrivateKey::generate().unwrap();
        let request: Value = serde_json::from_str(
            &signed_request(
                &key,
                Some("https://ca.example/account/1"),
                "next-nonce",
                "https://ca.example/order/1",
                b"",
            )
            .unwrap(),
        )
        .unwrap();

        let protected = decode_part(&request, "protected");
        assert_eq!(protected["kid"], "https://ca.example/account/1");
        assert!(protected.get("jwk").is_none());
        assert_eq!(request["payload"], "");
    }
}
