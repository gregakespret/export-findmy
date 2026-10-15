//! The anisette servers the exporter can sign in through.
//!
//! Since 2026-10-13 Apple refuses (`-80045`) a sign-in whose anisette comes
//! from Apple's *Android* ADI but claims an Apple device. Every public v3
//! server provisions Android ADI, and an Android identity gets only
//! `mmeAuthToken` back — no CloudKit, keychain or Find My access. A headers
//! server runs on a real Mac and returns AOSKit's own headers, so the sign-in
//! can claim the Mac identity they were generated for.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};
use reqwest::Url;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Where `--anisette-url` points when neither anisette flag is given.
pub const DEFAULT_V3_URL: &str = "https://ani.sidestore.io";

/// Above the Mac host's own 20 s limit on its helper, so a slow host still
/// answers, and well inside the 180 s a caller waits for a session to start.
const HEADERS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, PartialEq)]
pub enum AnisetteServer {
    /// SideStore's v3 protocol: the server provisions Android ADI for us.
    V3(String),
    /// A GET returns ready-made anisette headers as one JSON object.
    Headers(String),
}

impl AnisetteServer {
    /// The server named by the `--anisette-url` and `--anisette-headers-url`
    /// values. Checked at startup because a bad value otherwise boots a healthy
    /// server that fails every connect. The errors never echo the URL, whose
    /// path is a headers server's access secret.
    pub fn from_flags(v3: Option<String>, headers: Option<String>) -> Result<Self, String> {
        let (flag, url, server) = match (v3, headers) {
            (Some(_), Some(_)) => return Err("pass --anisette-url or --anisette-headers-url, not both".into()),
            (None, None) => return Ok(Self::V3(DEFAULT_V3_URL.into())),
            (Some(url), None) => ("--anisette-url", url.clone(), Self::V3(url)),
            (None, Some(url)) => ("--anisette-headers-url", url.clone(), Self::Headers(url)),
        };
        match Url::parse(&url) {
            _ if url.trim().is_empty() => Err(format!("{flag} is empty")),
            Ok(parsed) if matches!(parsed.scheme(), "http" | "https") && parsed.has_host() => Ok(server),
            _ => Err(format!("{flag} is not an http(s) URL")),
        }
    }
}

impl fmt::Display for AnisetteServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V3(url) => write!(f, "{url} (v3)"),
            // A headers server is private and its URL carries the access
            // secret, so only its origin reaches the log: no userinfo, path or
            // query, any of which can hold the secret.
            Self::Headers(url) => match Url::parse(url) {
                Ok(parsed) => write!(f, "{}/… (headers)", parsed.origin().ascii_serialization()),
                Err(_) => write!(f, "<invalid URL> (headers)"),
            },
        }
    }
}

// Not derived: a derived Debug prints a headers URL whole, secret included.
impl fmt::Debug for AnisetteServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub enum Provider {
    V3(Box<RemoteAnisetteProviderV3>),
    Headers(HeadersProvider),
}

impl Provider {
    pub fn new(server: &AnisetteServer, login_info: LoginClientInfo, state_dir: PathBuf) -> Self {
        match server {
            AnisetteServer::V3(url) => Self::V3(Box::new(RemoteAnisetteProviderV3::new(url.clone(), login_info, state_dir))),
            AnisetteServer::Headers(url) => Self::Headers(HeadersProvider::new(url.clone())),
        }
    }
}

impl AnisetteProvider for Provider {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        match self {
            Self::V3(p) => p.get_anisette_headers().await,
            Self::Headers(p) => p.get_anisette_headers().await,
        }
    }
}

pub struct HeadersProvider {
    url: String,
    http: reqwest::Client,
    local_user: String,
    device_id: String,
}

impl HeadersProvider {
    fn new(url: String) -> Self {
        // The server returns only what the Mac's ADI computes. AOSKit's own
        // local-user and device ids would identify the host Mac to every
        // account signed in through it, so each run mints its own, derived the
        // way the v3 provider derives them.
        let id: [u8; 16] = rand::random();
        HeadersProvider {
            url,
            // reqwest has no timeout by default, and this fetch reruns whenever
            // AnisetteClient's 60 s cache lapses, mid-export included.
            http: reqwest::Client::builder().timeout(HEADERS_TIMEOUT).build()
                .expect("reqwest client builds, as in Client::new"),
            local_user: Sha256::digest(id).iter().map(|b| format!("{b:02x}")).collect(),
            device_id: Uuid::from_bytes(id).to_string(),
        }
    }
}

impl AnisetteProvider for HeadersProvider {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        // reqwest names the URL in its errors, and the URL's path is the
        // server's access secret.
        let hide_url = reqwest::Error::without_url;
        let mut headers: HashMap<String, String> = self.http.get(&self.url).send().await.map_err(hide_url)?
            .error_for_status().map_err(hide_url)?
            .json().await.map_err(hide_url)?;
        // The login identity is read from X-Mme-Client-Info, so a reply
        // without it would sign in as nothing in particular.
        for name in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Client-Info"] {
            if !headers.contains_key(name) {
                return Err(AnisetteError::ServerError(format!("headers server sent no {name}")));
            }
        }
        headers.entry("X-Apple-I-MD-LU".into()).or_insert_with(|| self.local_user.clone());
        headers.entry("X-Mme-Device-Id".into()).or_insert_with(|| self.device_id.clone());
        Ok(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One-shot HTTP server answering a single request with `body`.
    async fn serve_once(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
        });
        url
    }

    #[test]
    fn headers_server_secret_path_stays_out_of_the_log() {
        let shown = AnisetteServer::Headers("https://mac.example:8443/s3cret/".into()).to_string();
        assert_eq!(shown, "https://mac.example:8443/… (headers)");
    }

    /// The Mac host keeps its secret in the path, but a URL can carry one in its
    /// userinfo or query just as well, and `{:?}` must hide it as `{}` does.
    #[test]
    fn headers_server_secret_outside_the_path_stays_out_of_the_log() {
        for url in ["https://user:s3cret@mac.example/", "https://mac.example?token=s3cret"] {
            let server = AnisetteServer::Headers(url.into());
            let shown = format!("{server} {server:?}");
            assert!(!shown.contains("s3cret"), "{shown}");
            assert!(shown.contains("https://mac.example"), "{shown}");
        }
    }

    /// A start command whose env var expanded to nothing, a URL without its
    /// scheme, or both modes at once must stop the boot rather than boot a
    /// server whose every connect fails. The refusal must not echo the URL.
    #[test]
    fn misconfigured_anisette_flags_are_refused_without_echoing_the_url() {
        let headers = |url: &str| AnisetteServer::from_flags(None, Some(url.into()));
        let both = AnisetteServer::from_flags(Some("https://ani.example".into()), Some("https://mac.example/s3cret".into()));
        for (result, reason) in [
            (headers(""), "empty"),
            (headers("  "), "empty"),
            (headers("mac.example/s3cret"), "not an http(s) URL"),
            (headers("ftp://mac.example/s3cret"), "not an http(s) URL"),
            (both, "not both"),
        ] {
            let error = result.unwrap_err();
            assert!(error.contains(reason) && !error.contains("s3cret"), "{error}");
        }
    }

    #[test]
    fn anisette_flags_pick_their_mode() {
        let mac = "https://mac.example/s3cret";
        assert_eq!(AnisetteServer::from_flags(None, Some(mac.into())), Ok(AnisetteServer::Headers(mac.into())));
        assert_eq!(AnisetteServer::from_flags(Some("http://localhost:6969".into()), None),
                   Ok(AnisetteServer::V3("http://localhost:6969".into())));
        assert_eq!(AnisetteServer::from_flags(None, None), Ok(AnisetteServer::V3(DEFAULT_V3_URL.into())));
    }

    /// The Mac sleeps, or the tunnel takes the connection and never answers.
    /// The fetch reruns whenever the 60 s header cache lapses, mid-export too,
    /// so without a bound it holds the session until the export timeout.
    #[tokio::test(start_paused = true)]
    async fn headers_server_that_never_answers_fails_the_fetch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/s3cret/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut provider = HeadersProvider::new(url);
        let fetch = provider.get_anisette_headers();
        let outcome = tokio::time::timeout(Duration::from_secs(300), fetch).await;
        assert!(matches!(outcome, Ok(Err(_))), "a silent server must fail the fetch, not hang it");
    }

    /// An unreachable host is the likeliest failure, and the pipeline logs the
    /// error whole: reqwest would put the URL, secret included, in that line.
    #[tokio::test]
    async fn headers_server_failure_keeps_the_secret_out_of_the_log() {
        let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/s3cret/");
        let error = HeadersProvider::new(url).get_anisette_headers().await.unwrap_err();
        let logged = format!("{error} [{error:?}]");
        assert!(!logged.contains("s3cret"), "{logged}");
    }

    /// Apple's sign-in requires the local-user and device ids, which a headers
    /// server leaves out so as not to expose its host's.
    #[tokio::test]
    async fn headers_server_reply_gains_per_run_device_ids() {
        let url = serve_once(r#"{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"machine","X-Mme-Client-Info":"<Mac17,4> <macOS;26.5;25F71> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"}"#).await;
        let mut provider = HeadersProvider::new(url);
        let headers = provider.get_anisette_headers().await.unwrap();
        assert_eq!(headers["X-Apple-I-MD-M"], "machine");
        assert_eq!(headers["X-Apple-I-MD-LU"].len(), 64);
        assert!(Uuid::parse_str(&headers["X-Mme-Device-Id"]).is_ok());
    }

    /// The sign-in claims the machine the server names, so a reply without
    /// that name must fail at the anisette step rather than sign in as nobody.
    #[tokio::test]
    async fn headers_server_reply_without_identity_is_refused() {
        let url = serve_once(r#"{"X-Apple-I-MD":"otp","X-Apple-I-MD-M":"machine"}"#).await;
        let error = HeadersProvider::new(url).get_anisette_headers().await.unwrap_err();
        assert!(error.to_string().contains("X-Mme-Client-Info"), "{error}");
    }
}
