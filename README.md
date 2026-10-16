# acme-client2

An asynchronous Rust library for issuing ACME certificates. The client handles
account registration, orders, validation, and certificate retrieval. Your
application serves the HTTP-01 challenge responses and installs the certificates.

Each order covers one DNS name. HTTP-01 is the only supported challenge method;
wildcard names and IP addresses are not supported.

## Setup

Requires Rust 1.88 or later and a Tokio runtime with I/O and time enabled.

```toml
[dependencies]
acme-client2 = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net", "time"] }
```

Start with your CA's staging directory while testing. Staging certificates are
not trusted by browsers. For Let's Encrypt, the directory URLs are:

| Environment | Directory URL |
| --- | --- |
| Staging | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| Production | `https://acme-v02.api.letsencrypt.org/directory` |

## Register and persist an account

Generate an `AccountKey` and save its `to_pkcs8_pem()` output in private storage
before registration. If registration is interrupted, retry with that same key.

The example below registers using an already saved key. Review the CA's terms
before calling `agree_to_terms_of_service()`; the client exposes the terms
URL through `terms_of_service_url()`.

```rust,no_run
use acme_client2::{
    AccountCredentials, AccountKey, AccountOptions, AcmeClient, Error,
};

async fn register(
    client: &AcmeClient,
    saved_key_pem: &str,
) -> Result<AccountCredentials, Error> {
    let key = AccountKey::from_pkcs8_pem(saved_key_pem)?;
    let account = client
        .create_account(
            key,
            AccountOptions::new()
                .contact("mailto:admin@example.com")
                .agree_to_terms_of_service(),
        )
        .await?;

    account.credentials()
}
```

Save the returned `AccountCredentials` for later runs. It implements Serde
serialization and contains the account's private key, so treat the entire value
as a secret. `restore_account()` loads it without a network request and requires
the exact directory URL used at registration. Staging and production accounts
are separate.

## Publish HTTP-01 challenges

Implement `Http01Handler` to connect the client to your HTTP server or challenge
store. It has two asynchronous methods:

- `present(&self, challenge: &Http01Challenge) -> Result<(), Error>` publishes
  the response. Return only when it is reachable by the CA.
- `cleanup(&self, challenge: &Http01Challenge) -> Result<(), Error>` removes
  the response. Removing an already absent response should succeed.

For each challenge, serve an HTTP `GET` on port 80 of `challenge.domain` at
`challenge.path()`. Return `challenge.key_authorization` as the exact response
body with a `text/plain` content type. Match the domain and path, and stop serving
the response at `challenge.expires_at`.

The library calls cleanup after success, failure, or its own issuance timeout,
including when publication only partially succeeds. Dropping the issuance future
or terminating the process prevents asynchronous cleanup, so the challenge store
must also enforce expiry.

`Http01Handler` implementations automatically implement `ChallengeHandler`.
Implement `ChallengeHandler` directly instead if you need method-aware dispatch;
its `supports()` method determines which challenges your handler accepts. Both
traits use static dispatch and require a concrete handler rather than a trait
object.

See [the Pebble integration test](https://github.com/ogital-net/acme-client2/blob/main/tests/pebble.rs)
for an HTTP server and handler used together.

## Issue or renew

Restore the account and pass your handler to `issue_certificate()`:

```rust,no_run
use acme_client2::{
    AccountCredentials, AcmeClient, Error, Http01Handler, IssuedCertificate,
};

async fn issue(
    credentials: AccountCredentials,
    handler: &impl Http01Handler,
) -> Result<IssuedCertificate, Error> {
    let client = AcmeClient::new(
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .await?;
    let account = client.restore_account(credentials)?;

    client.issue_certificate(&account, "example.com", handler).await
}
```

The result contains:

- `certificate_pem`: the PEM certificate chain, leaf first.
- `private_key_pem`: the matching private key in PKCS#8 PEM format.
- `not_after`: the leaf certificate's expiry time.

Every order generates a fresh certificate key, separate from the account key.
Your application is responsible for securely storing the result, updating its
TLS configuration, and scheduling renewal before `not_after`. Renewal uses the
same issuance call.

## Limits and errors

Use `AcmeClient::builder(directory_url)` to configure these defaults:

| Setting | Default |
| --- | --- |
| `request_timeout` | 30 seconds, also applied to each cleanup call |
| `issuance_timeout` | 10 minutes, excluding cleanup |
| `poll_interval` | 2 seconds |

Request and issuance timeouts must be positive. Polling uses the larger of the
configured interval and the CA's `Retry-After` value in seconds. Responses are
limited to 1 MiB.

TLS verification uses system root certificates. ACME URLs must share the
directory's origin unless you explicitly enable `allow_cross_origin_urls()`.
Use `danger_accept_invalid_certs()` only with a local test CA.

Before returning a certificate, the client checks the leaf's DNS name, public
key, and expiry, and verifies each certificate's signature against the next
certificate in the chain. It does not check `notBefore` or establish trust in a
root certificate.

Errors retain their concrete types inside the boxed `Error` type. Non-success
HTTP responses can be inspected as `AcmeProblem`:

```rust
use acme_client2::{AcmeProblem, Error};

fn report(error: &Error) {
    if let Some(problem) = error.downcast_ref::<AcmeProblem>() {
        eprintln!("ACME HTTP {}: {}", problem.status, problem);
    } else {
        eprintln!("Certificate issuance failed: {error}");
    }
}
```

An issuance error takes precedence if cleanup also fails. Otherwise, a cleanup
failure is returned as the error. If issuance fails after finalization, the CA
may have issued a certificate whose private key the client discards; allow enough
time for the CA to finish.

## Tests

Run the local tests and documentation examples:

```sh
cargo test --locked
```

The Pebble test performs issuance against a pinned local CA and serves real
HTTP-01 responses. It requires Docker, curl, and an available port 5002:

```sh
sh scripts/test-pebble.sh
```

The script starts Pebble, runs the integration test, and removes its container
and temporary files when it exits.
