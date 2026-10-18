//! HTTP(S) requests the request checks make themselves: JWKS (src/jwt) and OpenAPI specs
//! (src/apifw). rustls on aws-lc-rs with the Mozilla roots built in (the image has no CA store
//! of its own); every response under a size limit and a timeout; redirects are not followed.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::{HeaderMap, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::client::legacy::connect::HttpConnector;
use std::time::Duration;

pub type Client = hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

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
    let mut request = http::Request::get(uri.clone()).body(Empty::new())?;
    *request.headers_mut() = headers.clone();
    request
        .headers_mut()
        .entry(http::header::USER_AGENT)
        .or_insert(http::HeaderValue::from_static("web-server"));
    let work = async {
        let response = client.request(request).await.with_context(|| format!("GET {uri}"))?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, limit)
            .collect()
            .await
            .map_err(|e| anyhow!("GET {uri}: {e} (at most {limit} bytes)"))?
            .to_bytes();
        Ok(Fetched {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| anyhow!("GET {uri}: no answer within {} ms", timeout.as_millis()))?
}
