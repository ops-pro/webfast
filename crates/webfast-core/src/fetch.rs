//! HTTP(S) requests the request checks make themselves: JWKS (src/jwt), OpenAPI specs
//! (src/apifw), and what the modules fetch: address feeds, the CAPTCHA providers' verification.
//! rustls on aws-lc-rs with the Mozilla roots built in (the image has no CA store of its own);
//! every response under a size limit and a timeout; redirects are not followed.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use std::time::Duration;

pub type Client = hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub fn client() -> Result<Client> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(crate::tls::provider())
        .context("TLS for the server's own requests")?
        .https_or_http()
        .enable_http1()
        .build();
    Ok(hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https))
}

/// A response, read whole.
pub struct Fetched {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// GET `uri` with `headers`; the body at most `limit` bytes, everything within `timeout`.
pub async fn get(client: &Client, uri: &Uri, headers: &HeaderMap, limit: usize, timeout: Duration) -> Result<Fetched> {
    let mut request = http::Request::get(uri.clone()).body(Full::new(Bytes::new()))?;
    *request.headers_mut() = headers.clone();
    send(client, request, "GET", limit, timeout).await
}

/// POST `form` (`application/x-www-form-urlencoded`, already encoded) to `uri`; the body at most
/// `limit` bytes, everything within `timeout`.
pub async fn post_form(client: &Client, uri: &Uri, form: String, limit: usize, timeout: Duration) -> Result<Fetched> {
    let mut request = http::Request::post(uri.clone()).body(Full::new(Bytes::from(form)))?;
    request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    send(client, request, "POST", limit, timeout).await
}

async fn send(
    client: &Client,
    mut request: http::Request<Full<Bytes>>,
    method: &str,
    limit: usize,
    timeout: Duration,
) -> Result<Fetched> {
    let uri = request.uri().clone();
    request
        .headers_mut()
        .entry(http::header::USER_AGENT)
        .or_insert(HeaderValue::from_static("web-server"));
    let work = async {
        let response = client
            .request(request)
            .await
            .with_context(|| format!("{method} {uri}"))?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, limit)
            .collect()
            .await
            .map_err(|e| anyhow!("{method} {uri}: {e} (at most {limit} bytes)"))?
            .to_bytes();
        Ok(Fetched {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| anyhow!("{method} {uri}: no answer within {} ms", timeout.as_millis()))?
}
