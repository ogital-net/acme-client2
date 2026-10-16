use std::{
    convert::Infallible,
    fs,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use acme_client2::{
    AccountCredentials, AccountKey, AccountOptions, AcmeClient, Error, Http01Challenge,
    Http01Handler,
};
use bytes::Bytes;
use certutils::{
    Certificate, CertificateVerifier, DnsName, PrivateKey, SubjectAltName, VerificationOptions,
    VerificationPurpose,
};
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http1};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpListener, task::JoinHandle};

const DOMAIN: &str = "host.docker.internal";

#[derive(Default)]
struct State {
    publication: Option<Http01Challenge>,
    path: Option<String>,
    presentations: usize,
    cleanups: usize,
    served: usize,
}

struct Handler {
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Handler {
    async fn start() -> Self {
        let listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let state = server_state.clone();
                connections.spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let mut state = state.lock().unwrap();
                        let body = state
                            .publication
                            .as_ref()
                            .filter(|challenge| {
                                request.method() == Method::GET
                                    && request.uri().path() == challenge.path()
                                    && request
                                        .headers()
                                        .get("host")
                                        .and_then(|host| host.to_str().ok())
                                        == Some("host.docker.internal:5002")
                                    && challenge.expires_at > SystemTime::now()
                            })
                            .map(|challenge| challenge.key_authorization.clone());
                        let response = match body {
                            Some(body) => {
                                state.served += 1;
                                Response::builder()
                                    .header("content-type", "text/plain")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap()
                            }
                            None => Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        };
                        async { Ok::<_, Infallible>(response) }
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
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Http01Handler for Handler {
    async fn present(&self, challenge: &Http01Challenge) -> Result<(), Error> {
        assert_eq!(challenge.domain, DOMAIN);
        let mut state = self.state.lock().unwrap();
        assert!(state.publication.is_none());
        state.path = Some(challenge.path());
        state.publication = Some(challenge.clone());
        state.presentations += 1;
        Ok(())
    }

    async fn cleanup(&self, challenge: &Http01Challenge) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        if let Some(publication) = &state.publication {
            assert_eq!(publication.token, challenge.token);
        }
        state.publication = None;
        state.cleanups += 1;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires pinned Pebble and real HTTP-01; run sh scripts/test-pebble.sh"]
async fn pebble_http01_issuance() {
    let directory = std::env::var("PEBBLE_DIRECTORY_URL")
        .expect("run this test through sh scripts/test-pebble.sh");
    let test_dir = std::env::var("PEBBLE_TEST_DIR").unwrap();
    let builder = AcmeClient::builder(&directory)
        .danger_accept_invalid_certs()
        .request_timeout(Duration::from_secs(5))
        .issuance_timeout(Duration::from_secs(60))
        .poll_interval(Duration::from_millis(200));
    let handler = Handler::start().await;
    let client = builder.clone().build().await.unwrap();
    let key_path = std::path::Path::new(&test_dir).join("account-key.pem");
    fs::write(
        &key_path,
        AccountKey::generate().unwrap().to_pkcs8_pem().unwrap(),
    )
    .unwrap();
    let account = client
        .create_account(
            AccountKey::from_pkcs8_pem(&fs::read_to_string(&key_path).unwrap()).unwrap(),
            AccountOptions::new()
                .contact("mailto:admin@example.com")
                .agree_to_terms_of_service(),
        )
        .await
        .unwrap();
    let account_url = account.url().to_owned();
    let credentials_path = std::path::Path::new(&test_dir).join("account.json");
    fs::write(
        &credentials_path,
        serde_json::to_vec(&account.credentials().unwrap()).unwrap(),
    )
    .unwrap();
    drop(account);
    drop(client);

    let client = builder.build().await.unwrap();
    let credentials: AccountCredentials =
        serde_json::from_slice(&fs::read(credentials_path).unwrap()).unwrap();
    let account = client.restore_account(credentials).unwrap();
    assert_eq!(account.url(), account_url);
    let issued = client
        .issue_certificate(&account, DOMAIN, &handler)
        .await
        .unwrap();

    let path = {
        let state = handler.state.lock().unwrap();
        assert_eq!(state.presentations, 1);
        assert_eq!(state.cleanups, 1);
        assert!(
            state.served > 0,
            "Pebble must fetch the real HTTP-01 response"
        );
        assert!(state.publication.is_none());
        state.path.clone().unwrap()
    };
    let http = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        http.request(
            Request::builder()
                .uri(format!("http://127.0.0.1:5002{path}"))
                .header("host", "host.docker.internal:5002")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let chain = Certificate::from_pem_chain(&issued.certificate_pem).unwrap();
    assert!(
        chain.len() >= 2,
        "expected leaf and intermediate certificates"
    );
    let leaf = &chain[0];
    let subject = SubjectAltName::Dns(DnsName::new(DOMAIN).unwrap());
    assert_eq!(leaf.subject_alt_names().unwrap(), vec![subject.clone()]);
    let key = PrivateKey::from_pkcs8_pem(&issued.private_key_pem).unwrap();
    assert_eq!(leaf.public_key().unwrap(), key.public_key().unwrap());
    let now = SystemTime::now();
    let validity = leaf.validity().unwrap();
    assert!(validity.not_before() <= now);
    assert!(validity.not_after() > now);
    assert_eq!(issued.not_after, validity.not_after());
    let root = Certificate::from_pem(
        &fs::read_to_string(std::path::Path::new(&test_dir).join("root.pem")).unwrap(),
    )
    .unwrap();
    let verification = VerificationOptions::new(VerificationPurpose::TlsServer)
        .subject(subject)
        .at_time(now);
    let verifier = CertificateVerifier::new([root]);
    verifier.verify(leaf, &chain[1..], &verification).unwrap();
    assert!(verifier.verify(leaf, &[], &verification).is_err());
    assert!(
        CertificateVerifier::new([])
            .verify(leaf, &chain[1..], &verification)
            .is_err()
    );
}
