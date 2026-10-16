use std::{
    collections::HashSet,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use acme_client2::{
    Account, AccountKey, AccountOptions, AcmeClient, AcmeClientBuilder, AcmeProblem, Challenge,
    ChallengeHandler, ChallengeType, Error, Http01Challenge, Http01Handler,
};
use base64_simd::URL_SAFE_NO_PAD;
use bytes::Bytes;
use certutils::{
    Certificate, CertificateProfile, CertificateSigningRequest, DistinguishedName, DnsName,
    PrivateKey, SubjectAltName, Validity,
};
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jose4rs::{jwk::JsonWebKey, jws::JsonWebSignature};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_aws_lc::{ServerConfig, TlsAcceptor};

const DOMAIN: &str = "test.example";

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Success,
    BadNonceOnce,
    BadNonceAlways,
    InvalidAuthorization,
    UnsafeToken,
    WrongAuthorization,
    AlreadyAuthorized,
    PendingForever,
    WrongDomain,
    WrongKey,
    Expired,
    FutureNotBefore,
    UnrelatedChain,
    MissingCertificate,
    MissingLocation,
    DeactivatedAccount,
    CrossOriginAuthorization,
}

struct State {
    base: String,
    scenario: Scenario,
    challenge_types: Vec<&'static str>,
    issuer_key: PrivateKey,
    issuer: Certificate,
    account_jwk: Option<JsonWebKey>,
    nonces: HashSet<String>,
    nonce_count: usize,
    response_nonces: usize,
    registrations: usize,
    order_polls: usize,
    ready: bool,
    acknowledged: bool,
    certificate_pem: Option<String>,
    publication: Option<Http01Challenge>,
    events: Vec<&'static str>,
}

impl State {
    /// The same test server, reached through a different origin.
    fn alternate_base(&self) -> String {
        self.base.replace("127.0.0.1", "localhost")
    }

    fn order(&self, status: &str) -> Value {
        let authorization_base = if self.scenario == Scenario::CrossOriginAuthorization {
            self.alternate_base()
        } else {
            self.base.clone()
        };
        json!({
            "status": status,
            "authorizations": [format!("{authorization_base}/auth/1")],
            "finalize": format!("{}/finalize/1", self.base),
            "certificate": if self.scenario == Scenario::MissingCertificate {
                None
            } else {
                Some(format!("{}/certificate/1", self.base))
            }
        })
    }

    fn dispatch(&mut self, request: Request<Bytes>) -> Response<Full<Bytes>> {
        let is_post = request.method() == Method::POST;
        let mut response = self.route(request);
        if is_post && !response.headers().contains_key("replay-nonce") {
            self.response_nonces += 1;
            let nonce = format!("response-{}", self.response_nonces);
            self.nonces.insert(nonce.clone());
            response
                .headers_mut()
                .insert("replay-nonce", nonce.parse().unwrap());
        }
        response
    }

    fn route(&mut self, request: Request<Bytes>) -> Response<Full<Bytes>> {
        let path = request.uri().path();
        if path == "/directory" {
            assert_eq!(request.method(), Method::GET);
            return json_response(
                200,
                json!({
                    "newNonce": format!("{}/nonce", self.base),
                    "newAccount": format!("{}/account", self.base),
                    "newOrder": format!("{}/order", self.base),
                    "meta": { "termsOfService": "https://ca.example/terms" }
                }),
            );
        }
        if path == "/nonce" {
            assert_eq!(request.method(), Method::HEAD);
            self.nonce_count += 1;
            let nonce = format!("nonce-{}", self.nonce_count);
            self.nonces.insert(nonce.clone());
            return Response::builder()
                .status(200)
                .header("replay-nonce", nonce)
                .body(Full::new(Bytes::new()))
                .unwrap();
        }
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.headers()["content-type"], "application/jose+json");
        assert!(
            request.headers()["user-agent"]
                .to_str()
                .unwrap()
                .starts_with("acme-client2/")
        );
        let envelope: Value = serde_json::from_slice(request.body()).unwrap();
        let protected: Value = serde_json::from_slice(&decode(&envelope, "protected")).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert!(
            [&self.base, &self.alternate_base()]
                .iter()
                .any(|base| protected["url"] == format!("{base}{path}"))
        );
        assert!(self.nonces.remove(protected["nonce"].as_str().unwrap()));
        if path == "/account" {
            assert!(protected.get("kid").is_none());
            assert!(protected["jwk"].get("d").is_none());
            self.account_jwk = Some(
                JsonWebKey::from_json(serde_json::to_vec(&protected["jwk"]).unwrap()).unwrap(),
            );
        } else {
            assert_eq!(protected["kid"], format!("{}/account/1", self.base));
            assert!(protected.get("jwk").is_none());
        }
        let signature =
            JsonWebSignature::from_flattened_json_serialization(request.body()).unwrap();
        assert!(
            signature
                .verify_signature(self.account_jwk.as_ref().unwrap())
                .unwrap()
        );
        let payload = decode(&envelope, "payload");
        match path {
            "/account" => {
                self.registrations += 1;
                if self.scenario == Scenario::BadNonceAlways
                    || (self.scenario == Scenario::BadNonceOnce && self.registrations == 1)
                {
                    let nonce = format!("retry-{}", self.registrations);
                    self.nonces.insert(nonce.clone());
                    let mut response = json_response(
                        400,
                        json!({
                            "type": "urn:ietf:params:acme:error:badNonce", "detail": "retry this nonce"
                        }),
                    );
                    response
                        .headers_mut()
                        .insert("replay-nonce", nonce.parse().unwrap());
                    return response;
                }
                let payload: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(payload["termsOfServiceAgreed"], true);
                assert_eq!(payload["contact"], json!(["mailto:admin@test.example"]));
                let account_status = if self.scenario == Scenario::DeactivatedAccount {
                    "deactivated"
                } else {
                    "valid"
                };
                let mut response = json_response(201, json!({ "status": account_status }));
                if self.scenario != Scenario::MissingLocation {
                    response.headers_mut().insert(
                        "location",
                        format!("{}/account/1", self.base).parse().unwrap(),
                    );
                }
                response
            }
            "/order" => {
                let payload: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(
                    payload["identifiers"],
                    json!([{ "type": "dns", "value": DOMAIN }])
                );
                let mut response = json_response(201, self.order("pending"));
                response.headers_mut().insert(
                    "location",
                    format!("{}/order/1", self.base).parse().unwrap(),
                );
                response
            }
            "/auth/1" => {
                assert!(payload.is_empty());
                let status = if self.scenario == Scenario::AlreadyAuthorized {
                    "valid"
                } else if !self.acknowledged || self.scenario == Scenario::PendingForever {
                    "pending"
                } else if self.scenario == Scenario::InvalidAuthorization {
                    "invalid"
                } else {
                    "valid"
                };
                let failed = status == "invalid";
                let challenges: Vec<_> = self.challenge_types.iter().map(|kind| {
                    let path = if *kind == "http-01" { "1" } else { "unsupported" };
                    json!({
                        "type": kind,
                        "url": format!("{}/challenge/{path}", self.base),
                        "token": if self.scenario == Scenario::UnsafeToken { "../unsafe" } else { "token-123_ABC" },
                        "error": if failed && *kind == "http-01" {
                            json!({ "type": "urn:ietf:params:acme:error:connection", "detail": "connection refused" })
                        } else {
                            Value::Null
                        }
                    })
                }).collect();
                json_response(
                    200,
                    json!({
                        "status": status,
                        "identifier": { "type": "dns", "value": if self.scenario == Scenario::WrongAuthorization { "other.example" } else { DOMAIN } },
                        "challenges": challenges
                    }),
                )
            }
            "/challenge/1" => {
                assert_eq!(
                    serde_json::from_slice::<Value>(&payload).unwrap(),
                    json!({})
                );
                let challenge = self
                    .publication
                    .as_ref()
                    .expect("challenge must be published before acknowledgement");
                assert_eq!(
                    challenge.path(),
                    "/.well-known/acme-challenge/token-123_ABC"
                );
                assert_eq!(challenge.domain, DOMAIN);
                assert_eq!(
                    challenge.key_authorization,
                    format!(
                        "token-123_ABC.{}",
                        self.account_jwk.as_ref().unwrap().thumbprint().unwrap()
                    )
                );
                assert!(challenge.expires_at > SystemTime::now());
                self.acknowledged = true;
                self.events.push("acknowledge");
                json_response(200, json!({ "status": "processing" }))
            }
            "/order/1" => {
                assert!(payload.is_empty());
                self.order_polls += 1;
                let status = if self.certificate_pem.is_some() {
                    "valid"
                } else if self.order_polls == 1 {
                    "pending"
                } else {
                    self.ready = true;
                    "ready"
                };
                json_response(200, self.order(status))
            }
            "/finalize/1" => {
                assert!(self.ready, "client must wait for ready before finalizing");
                self.events.push("finalize");
                let payload: Value = serde_json::from_slice(&payload).unwrap();
                let csr = CertificateSigningRequest::from_der(
                    &URL_SAFE_NO_PAD
                        .decode_to_vec(payload["csr"].as_str().unwrap().as_bytes())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    csr.subject_alt_names().unwrap(),
                    vec![SubjectAltName::Dns(DnsName::new(DOMAIN).unwrap())]
                );
                let domain = if self.scenario == Scenario::WrongDomain {
                    "wrong.example"
                } else {
                    DOMAIN
                };
                let now = SystemTime::now();
                let hour = Duration::from_secs(3600);
                let (start, end) = match self.scenario {
                    Scenario::Expired => (now - 2 * hour, now - hour),
                    Scenario::FutureNotBefore => (now + Duration::from_secs(60), now + hour),
                    _ => (now - hour, now + hour),
                };
                let key = if self.scenario == Scenario::WrongKey {
                    PrivateKey::generate().unwrap().public_key().unwrap()
                } else {
                    csr.public_key().unwrap()
                };
                let leaf = Certificate::builder(
                    name(domain),
                    Validity::new(start, end).unwrap(),
                    CertificateProfile::Server,
                )
                .dns_name(DnsName::new(domain).unwrap())
                .signed_by(&key, &self.issuer, &self.issuer_key)
                .unwrap();
                let intermediate = if self.scenario == Scenario::UnrelatedChain {
                    let other_key = PrivateKey::generate().unwrap();
                    Certificate::builder(
                        name("Test CA"),
                        self.issuer.validity().unwrap(),
                        CertificateProfile::CertificateAuthority { path_length: None },
                    )
                    .self_signed(&other_key)
                    .unwrap()
                } else {
                    self.issuer.clone()
                };
                self.certificate_pem = Some(format!(
                    "{}{}",
                    leaf.to_pem().unwrap(),
                    intermediate.to_pem().unwrap()
                ));
                json_response(200, self.order("processing"))
            }
            "/certificate/1" => {
                assert!(payload.is_empty());
                Response::builder()
                    .header("content-type", "application/pem-certificate-chain")
                    .body(Full::new(Bytes::from(
                        self.certificate_pem.clone().unwrap(),
                    )))
                    .unwrap()
            }
            _ => panic!("unexpected request: {path}"),
        }
    }
}

fn name(common_name: &str) -> DistinguishedName {
    DistinguishedName::builder()
        .common_name(common_name)
        .build()
        .unwrap()
}

fn decode(envelope: &Value, field: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode_to_vec(envelope[field].as_str().unwrap().as_bytes())
        .unwrap()
}

fn json_response(status: u16, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

struct TestCa {
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl TestCa {
    async fn start(scenario: Scenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("https://{}", listener.local_addr().unwrap());
        let issuer_key = PrivateKey::generate().unwrap();
        let now = SystemTime::now();
        let issuer = Certificate::builder(
            name("Test CA"),
            Validity::new(
                now - Duration::from_secs(86400),
                now + Duration::from_secs(86400),
            )
            .unwrap(),
            CertificateProfile::CertificateAuthority { path_length: None },
        )
        .self_signed(&issuer_key)
        .unwrap();
        let tls_certificate = Certificate::builder(
            name("localhost"),
            issuer.validity().unwrap(),
            CertificateProfile::Server,
        )
        .ip_address("127.0.0.1".parse().unwrap())
        .self_signed(&issuer_key)
        .unwrap();
        let tls = TlsAcceptor::new(Arc::new(
            ServerConfig::builder()
                .with_pem_bytes(
                    tls_certificate.to_pem().unwrap().as_bytes(),
                    issuer_key.to_pkcs8_pem().unwrap().as_bytes(),
                )
                .unwrap(),
        ));
        let state = Arc::new(Mutex::new(State {
            base,
            scenario,
            challenge_types: vec!["http-01"],
            issuer_key,
            issuer,
            account_jwk: None,
            nonces: HashSet::new(),
            nonce_count: 0,
            response_nonces: 0,
            registrations: 0,
            order_polls: 0,
            ready: false,
            acknowledged: false,
            certificate_pem: None,
            publication: None,
            events: Vec::new(),
        }));
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let state = server_state.clone();
                let tls = tls.clone();
                connections.spawn(async move {
                    let stream = tls.accept(stream).await.unwrap();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = state.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body.collect().await.unwrap().to_bytes();
                            let response = state
                                .lock()
                                .unwrap()
                                .dispatch(Request::from_parts(parts, body));
                            Ok::<_, Infallible>(response)
                        }
                    });
                    http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .unwrap();
                });
            }
        });
        Self { state, task }
    }

    fn builder(&self) -> AcmeClientBuilder {
        let url = format!("{}/directory", self.state.lock().unwrap().base);
        AcmeClient::builder(url)
            .danger_accept_invalid_certs()
            .request_timeout(Duration::from_secs(2))
            .issuance_timeout(Duration::from_secs(2))
            .poll_interval(Duration::from_millis(1))
    }

    async fn client(&self) -> AcmeClient {
        self.builder().build().await.unwrap()
    }

    fn handler(&self, behavior: Behavior) -> Handler {
        Handler {
            state: self.state.clone(),
            behavior,
        }
    }
}

impl Drop for TestCa {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    FailPresent,
    HangPresent,
    FailCleanup,
    HangCleanup,
}

struct Handler {
    state: Arc<Mutex<State>>,
    behavior: Behavior,
}

impl Http01Handler for Handler {
    async fn present(&self, challenge: &Http01Challenge) -> Result<(), Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.events.push("present");
            state.publication = Some(challenge.clone());
        }
        match self.behavior {
            Behavior::FailPresent => Err(std::io::Error::other("publication failed").into()),
            Behavior::HangPresent => std::future::pending().await,
            _ => Ok(()),
        }
    }

    async fn cleanup(&self, challenge: &Http01Challenge) -> Result<(), Error> {
        {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.publication.as_ref().unwrap().token, challenge.token);
            state.publication = None;
            state.events.push("cleanup");
        }
        match self.behavior {
            Behavior::FailCleanup => Err(std::io::Error::other("cleanup failed").into()),
            Behavior::HangCleanup => std::future::pending().await,
            _ => Ok(()),
        }
    }
}

struct MethodAwareHandler {
    http: Handler,
    accept_http01: bool,
}

impl ChallengeHandler for MethodAwareHandler {
    fn supports(&self, challenge_type: ChallengeType) -> bool {
        self.accept_http01 && matches!(challenge_type, ChallengeType::Http01)
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), Error> {
        assert_eq!(challenge.challenge_type().as_str(), "http-01");
        match challenge {
            Challenge::Http01(challenge) => Http01Handler::present(&self.http, challenge).await,
            _ => Err(std::io::Error::other("unsupported challenge method").into()),
        }
    }

    async fn cleanup(&self, challenge: &Challenge) -> Result<(), Error> {
        match challenge {
            Challenge::Http01(challenge) => Http01Handler::cleanup(&self.http, challenge).await,
            _ => Err(std::io::Error::other("unsupported challenge method").into()),
        }
    }
}

#[tokio::test]
async fn method_aware_handler_selects_supported_challenges_and_cleans_up() {
    for (scenario, behavior, error_message) in [
        (Scenario::Success, Behavior::Normal, None),
        (
            Scenario::InvalidAuthorization,
            Behavior::Normal,
            Some("authorization is invalid"),
        ),
        (
            Scenario::Success,
            Behavior::HangPresent,
            Some("issuance timed out"),
        ),
    ] {
        let ca = TestCa::start(scenario).await;
        ca.state.lock().unwrap().challenge_types =
            vec!["dns-01", "tls-alpn-01", "future-01", "http-01"];
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let handler = MethodAwareHandler {
            http: ca.handler(behavior),
            accept_http01: true,
        };
        let result = client.issue_certificate(&account, DOMAIN, &handler).await;
        match error_message {
            Some(message) => assert!(result.err().unwrap().to_string().contains(message)),
            None => {
                result.unwrap();
            }
        }
        let state = ca.state.lock().unwrap();
        assert_eq!(state.events.first(), Some(&"present"));
        assert_eq!(state.events.last(), Some(&"cleanup"));
        assert!(state.publication.is_none());
    }
}

#[tokio::test]
async fn unsupported_challenges_fail_before_publication_or_acknowledgement() {
    for (challenge_types, accept_http01) in [
        (vec!["http-01"], false),
        (vec!["dns-01", "tls-alpn-01", "future-01"], true),
        (vec![], true),
    ] {
        let ca = TestCa::start(Scenario::Success).await;
        ca.state.lock().unwrap().challenge_types = challenge_types;
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let handler = MethodAwareHandler {
            http: ca.handler(Behavior::Normal),
            accept_http01,
        };
        let error = client
            .issue_certificate(&account, DOMAIN, &handler)
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("no supported challenge"),
            "{error}"
        );
        let state = ca.state.lock().unwrap();
        assert!(state.events.is_empty());
        assert!(!state.acknowledged);
        assert!(state.publication.is_none());
    }
}

async fn register(client: &AcmeClient) -> Result<Account, Error> {
    let key = AccountKey::generate()?;
    let saved_key = key.to_pkcs8_pem()?;
    client
        .create_account(
            AccountKey::from_pkcs8_pem(&saved_key)?,
            AccountOptions::new()
                .contact("mailto:admin@test.example")
                .agree_to_terms_of_service(),
        )
        .await
}

#[tokio::test]
async fn issues_certificate_with_restored_credentials_and_cleans_up() {
    let ca = TestCa::start(Scenario::Success).await;
    let client = ca.client().await;
    assert!(format!("{client:?}").contains("AcmeClient"));
    assert_eq!(
        client.terms_of_service_url(),
        Some("https://ca.example/terms")
    );
    let account = register(&client).await.unwrap();
    let credentials = account.credentials().unwrap();
    let restored_key = AccountKey::from_pkcs8_pem(&credentials.private_key_pem).unwrap();
    for debug in [
        format!("{credentials:?}"),
        format!("{account:?}"),
        format!("{restored_key:?}"),
    ] {
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));
        assert!(!debug.contains(&credentials.private_key_pem));
    }
    let serialized = serde_json::to_vec(&credentials).unwrap();
    let restored = client
        .restore_account(serde_json::from_slice(&serialized).unwrap())
        .unwrap();
    assert_eq!(restored.url(), account.url());
    let certificate = client
        .issue_certificate(&restored, DOMAIN, &ca.handler(Behavior::Normal))
        .await
        .unwrap();
    let chain = Certificate::from_pem_chain(&certificate.certificate_pem).unwrap();
    let debug = format!("{certificate:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(&certificate.private_key_pem));
    assert!(!debug.contains(&certificate.certificate_pem));
    assert_eq!(chain.len(), 2);
    let key = PrivateKey::from_pkcs8_pem(&certificate.private_key_pem).unwrap();
    assert_eq!(chain[0].public_key().unwrap(), key.public_key().unwrap());
    let account_key = PrivateKey::from_pkcs8_pem(&credentials.private_key_pem).unwrap();
    assert_ne!(key.public_key().unwrap(), account_key.public_key().unwrap());
    assert_eq!(
        certificate.not_after,
        chain[0].validity().unwrap().not_after()
    );
    let state = ca.state.lock().unwrap();
    assert_eq!(
        state.events,
        ["present", "acknowledge", "finalize", "cleanup"]
    );
    assert!(state.publication.is_none());
    assert_eq!(state.nonce_count, 1, "response nonces should be reused");
}

#[tokio::test]
async fn accepts_certificates_with_slightly_future_not_before() {
    let ca = TestCa::start(Scenario::FutureNotBefore).await;
    let client = ca.client().await;
    let account = register(&client).await.unwrap();
    client
        .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
        .await
        .unwrap();
}

#[tokio::test]
async fn builder_rejects_zero_timeouts() {
    let ca = TestCa::start(Scenario::Success).await;
    for builder in [
        ca.builder().request_timeout(Duration::ZERO),
        ca.builder().issuance_timeout(Duration::ZERO),
    ] {
        let error = builder.build().await.err().unwrap();
        assert!(error.to_string().contains("must be positive"), "{error}");
    }
}

#[tokio::test]
async fn bad_nonce_retries_use_response_nonce_and_are_bounded() {
    for (scenario, attempts) in [(Scenario::BadNonceOnce, 2), (Scenario::BadNonceAlways, 3)] {
        let ca = TestCa::start(scenario).await;
        let result = register(&ca.client().await).await;
        if scenario == Scenario::BadNonceOnce {
            assert!(result.is_ok());
        } else {
            let error = result.err().unwrap();
            let problem = error.downcast_ref::<AcmeProblem>().unwrap();
            assert_eq!(problem.status, 400);
            assert_eq!(
                problem.problem_type.as_deref(),
                Some("urn:ietf:params:acme:error:badNonce")
            );
            assert_eq!(
                problem.to_string(),
                "ACME server returned 400: urn:ietf:params:acme:error:badNonce: retry this nonce"
            );
        }
        let state = ca.state.lock().unwrap();
        assert_eq!(state.registrations, attempts);
        assert_eq!(state.nonce_count, 1);
    }
}

#[tokio::test]
async fn invalid_server_results_fail_and_remove_challenges() {
    for (scenario, message) in [
        (
            Scenario::InvalidAuthorization,
            "authorization is invalid: urn:ietf:params:acme:error:connection: connection refused",
        ),
        (Scenario::PendingForever, "issuance timed out"),
        (Scenario::WrongDomain, "requested DNS name"),
        (Scenario::WrongKey, "does not match the private key"),
        (Scenario::Expired, "has expired"),
        (Scenario::UnrelatedChain, "chain is not correctly ordered"),
        (Scenario::MissingCertificate, "no certificate URL"),
    ] {
        let ca = TestCa::start(scenario).await;
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let error = client
            .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
        let state = ca.state.lock().unwrap();
        assert_eq!(state.events.last(), Some(&"cleanup"));
        assert!(state.publication.is_none());
    }
}

#[tokio::test]
async fn unsafe_or_unrelated_challenges_are_never_published() {
    for (scenario, message) in [
        (Scenario::UnsafeToken, "invalid characters"),
        (Scenario::WrongAuthorization, "does not match"),
        (Scenario::CrossOriginAuthorization, "different origin"),
    ] {
        let ca = TestCa::start(scenario).await;
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let error = client
            .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
        assert!(ca.state.lock().unwrap().events.is_empty());
    }
}

#[tokio::test]
async fn cross_origin_urls_can_be_explicitly_allowed() {
    let ca = TestCa::start(Scenario::CrossOriginAuthorization).await;
    let client = ca
        .builder()
        .allow_cross_origin_urls()
        .build()
        .await
        .unwrap();
    let account = register(&client).await.unwrap();
    client
        .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
        .await
        .unwrap();
}

#[tokio::test]
async fn already_valid_authorizations_need_no_publication() {
    let ca = TestCa::start(Scenario::AlreadyAuthorized).await;
    let client = ca.client().await;
    let account = register(&client).await.unwrap();
    client
        .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
        .await
        .unwrap();
    assert_eq!(ca.state.lock().unwrap().events, ["finalize"]);
}

#[tokio::test]
async fn partial_publication_and_issuance_timeout_both_clean_up() {
    for (behavior, message) in [
        (Behavior::FailPresent, "publication failed"),
        (Behavior::HangPresent, "issuance timed out"),
    ] {
        let ca = TestCa::start(Scenario::Success).await;
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let error = client
            .issue_certificate(&account, DOMAIN, &ca.handler(behavior))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
        assert_eq!(ca.state.lock().unwrap().events, ["present", "cleanup"]);
    }
}

#[tokio::test]
async fn cleanup_errors_are_bounded_and_do_not_mask_issuance_errors() {
    for (scenario, behavior, message) in [
        (Scenario::Success, Behavior::FailCleanup, "cleanup failed"),
        (
            Scenario::Success,
            Behavior::HangCleanup,
            "cleanup timed out",
        ),
        (
            Scenario::InvalidAuthorization,
            Behavior::FailCleanup,
            "authorization is invalid",
        ),
    ] {
        let ca = TestCa::start(scenario).await;
        let client = ca.client().await;
        let account = register(&client).await.unwrap();
        let error = client
            .issue_certificate(&account, DOMAIN, &ca.handler(behavior))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[tokio::test]
async fn rejects_cross_directory_accounts_and_wildcards_before_ordering() {
    let ca = TestCa::start(Scenario::Success).await;
    let client = ca.client().await;
    let account = register(&client).await.unwrap();
    let mut credentials = account.credentials().unwrap();
    credentials.directory_url = "https://other.example/directory".into();
    assert!(client.restore_account(credentials).is_err());
    let other = TestCa::start(Scenario::Success).await;
    assert!(
        other
            .client()
            .await
            .issue_certificate(&account, DOMAIN, &ca.handler(Behavior::Normal))
            .await
            .is_err()
    );
    for name in ["*.test.example", "*", "127.0.0.1", "::1"] {
        assert!(
            client
                .issue_certificate(&account, name, &ca.handler(Behavior::Normal))
                .await
                .is_err()
        );
    }
    assert!(ca.state.lock().unwrap().events.is_empty());
}

#[tokio::test]
async fn registration_requires_valid_account() {
    let ca = TestCa::start(Scenario::DeactivatedAccount).await;
    let error = register(&ca.client().await).await.err().unwrap();
    assert!(error.to_string().contains("account is deactivated"));
}

#[tokio::test]
async fn registration_requires_location_header() {
    let ca = TestCa::start(Scenario::MissingLocation).await;
    let error = register(&ca.client().await).await.err().unwrap();
    assert!(error.to_string().contains("no Location header"));
}

#[test]
fn public_types_implement_debug_send_and_sync() {
    fn assert_traits<PublicType: std::fmt::Debug + Send + Sync>() {}
    assert_traits::<AcmeClient>();
    assert_traits::<AccountKey>();
    assert_traits::<Account>();
    assert_traits::<acme_client2::AccountCredentials>();
    assert_traits::<AcmeClientBuilder>();
    assert_traits::<AccountOptions>();
    assert_traits::<ChallengeType>();
    assert_traits::<Challenge>();
    assert_traits::<Http01Challenge>();
    assert_traits::<acme_client2::IssuedCertificate>();
    assert_traits::<AcmeProblem>();
    assert_traits::<Error>();
}

#[test]
fn rust_sources_are_ascii() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut pending = vec![root.join("src"), root.join("tests")];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let contents = std::fs::read(&path).unwrap();
            assert!(contents.is_ascii(), "non-ASCII source: {}", path.display());
        }
    }
}

#[test]
fn challenge_types_support_standard_conversions_and_collections() {
    let kinds = HashSet::from([ChallengeType::Http01]);
    assert!(kinds.contains(&ChallengeType::Http01));
    assert_eq!(ChallengeType::Http01.as_ref(), "http-01");
    assert_eq!(ChallengeType::Http01.to_string(), "http-01");
    let http = Http01Challenge {
        domain: DOMAIN.into(),
        token: "token".into(),
        key_authorization: "token.thumbprint".into(),
        expires_at: SystemTime::now(),
    };
    let challenge: Challenge = http.into();
    assert_eq!(challenge.challenge_type(), ChallengeType::Http01);
}
