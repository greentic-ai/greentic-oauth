use std::{pin::Pin, str::FromStr, sync::Arc};

use base64::Engine;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{
        self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        ReadHalf, WriteHalf,
    },
    net::TcpStream,
    sync::Mutex,
    task::JoinHandle,
};
use tokio_rustls::{self, rustls, TlsConnector};
use tracing::{info, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::{
    http::{
        error::AppError,
        handlers::initiate::{process_start, StartRequest},
        SharedContext,
    },
    storage::{index::OwnerKindKey, models::Visibility, secrets_manager::SecretsManager},
    telemetry_nats::{self, NatsHeaders},
    tokens::{perform_signed_fetch, resolve_access_token, SignedFetchOptions, SignedFetchOutcome},
};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type DynStream = Pin<Box<dyn AsyncReadWrite>>;

#[derive(Debug, Error)]
pub enum NatsError {
    #[error("missing environment variable {0}")]
    MissingEnv(&'static str),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[derive(Clone, Debug)]
pub struct NatsOptions {
    pub url: String,
    pub tls_domain: Option<String>,
}

impl NatsOptions {
    pub fn from_env() -> Result<Self, NatsError> {
        let url = std::env::var("NATS_URL").map_err(|_| NatsError::MissingEnv("NATS_URL"))?;
        let tls_domain = std::env::var("NATS_TLS_DOMAIN").ok();
        Ok(Self { url, tls_domain })
    }
}

async fn handle_start_request<S>(
    parts: &[&str],
    payload: &[u8],
    ctx: &SharedContext<S>,
) -> Result<Vec<u8>, NatsError>
where
    S: SecretsManager + 'static,
{
    if parts.len() != 7 {
        return Err(NatsError::InvalidRequest(format!(
            "subject `{}` does not match oauth.req.* pattern",
            parts.join(".")
        )));
    }

    let tenant = parts[2].to_string();
    let env = parts[3].to_string();
    let team = match parts[4] {
        "_" => None,
        other => Some(other.to_string()),
    };
    let provider = parts[5].to_string();
    let flow_id = parts[6].to_string();

    let value: Value = if payload.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(payload)?
    };

    let owner_kind = value
        .get("owner_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| NatsError::InvalidRequest("owner_kind missing".into()))?;
    let owner_kind = OwnerKindKey::from_str(owner_kind)
        .map_err(|_| NatsError::InvalidRequest("invalid owner_kind".into()))?;
    let owner_id = value
        .get("owner_id")
        .and_then(Value::as_str)
        .ok_or_else(|| NatsError::InvalidRequest("owner_id missing".into()))?
        .to_string();

    let scopes = match value.get("scopes") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|entry| entry.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => s
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        _ => Vec::new(),
    };

    let visibility = value
        .get("visibility")
        .and_then(Value::as_str)
        .map(Visibility::from_str)
        .transpose()
        .map_err(|_| NatsError::InvalidRequest("invalid visibility".into()))?
        .unwrap_or(Visibility::Private);

    let redirect_uri = value
        .get("redirect_uri")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let request = StartRequest {
        env,
        tenant,
        provider,
        team,
        owner_kind,
        owner_id,
        flow_id: flow_id.clone(),
        scopes,
        redirect_uri,
        visibility,
    };

    let (redirect_url, state_token, _flow_state) = process_start(ctx, &request)
        .await
        .map_err(|err| NatsError::InvalidRequest(format!("{err:?}")))?;

    let response = serde_json::json!({
        "flow_id": flow_id,
        "redirect_url": redirect_url,
        "state": state_token,
    });
    Ok(serde_json::to_vec(&response)?)
}

async fn handle_token_get<S>(payload: &[u8], ctx: &SharedContext<S>) -> Result<Vec<u8>, NatsError>
where
    S: SecretsManager + 'static,
{
    let request: TokenGetMessage = serde_json::from_slice(payload)?;
    let response = resolve_access_token(ctx, &request.token_handle, request.force_refresh)
        .await
        .map_err(map_app_error)?;
    Ok(serde_json::to_vec(&response)?)
}

async fn handle_signed_fetch<S>(
    payload: &[u8],
    ctx: &SharedContext<S>,
) -> Result<Vec<u8>, NatsError>
where
    S: SecretsManager + 'static,
{
    let request: SignedFetchMessage = serde_json::from_slice(payload)?;
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| NatsError::InvalidRequest("invalid HTTP method".into()))?;
    let body = request.decode_body()?;
    let headers = request
        .headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();

    let outcome = perform_signed_fetch(
        ctx,
        SignedFetchOptions {
            token_handle: request.token_handle,
            method,
            url: request.url,
            headers,
            body,
        },
    )
    .await
    .map_err(map_app_error)?;

    Ok(serde_json::to_vec(&SignedFetchEnvelope::from(outcome))?)
}

#[derive(Deserialize)]
struct TokenGetMessage {
    token_handle: String,
    #[serde(default)]
    force_refresh: bool,
}

#[derive(Deserialize)]
struct SignedFetchMessage {
    token_handle: String,
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<SignedFetchHeader>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_encoding: BodyEncoding,
}

impl SignedFetchMessage {
    fn decode_body(&self) -> Result<Option<Vec<u8>>, NatsError> {
        match (&self.body, self.body_encoding) {
            (None, _) => Ok(None),
            (Some(payload), BodyEncoding::Base64) => base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map(Some)
                .map_err(|err| NatsError::InvalidRequest(format!("invalid base64 body: {err}"))),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SignedFetchHeader {
    name: String,
    value: String,
}

#[derive(Copy, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum BodyEncoding {
    #[default]
    Base64,
}

#[derive(Serialize)]
struct SignedFetchEnvelope {
    status: u16,
    headers: Vec<SignedFetchHeader>,
    body: String,
    body_encoding: &'static str,
}

impl From<SignedFetchOutcome> for SignedFetchEnvelope {
    fn from(value: SignedFetchOutcome) -> Self {
        let encoded_body = base64::engine::general_purpose::STANDARD.encode(value.body);
        let headers = value
            .headers
            .into_iter()
            .map(|(name, value)| SignedFetchHeader { name, value })
            .collect();
        Self {
            status: value.status,
            headers,
            body: encoded_body,
            body_encoding: "base64",
        }
    }
}

fn map_app_error(err: AppError) -> NatsError {
    NatsError::InvalidRequest(err.to_string())
}

pub struct Writer {
    inner: Mutex<WriteHalf<DynStream>>,
}

impl Writer {
    async fn write_command(&self, command: &str) -> Result<(), NatsError> {
        let mut guard = self.inner.lock().await;
        guard.write_all(command.as_bytes()).await?;
        guard.flush().await?;
        Ok(())
    }

    async fn publish(
        &self,
        subject: &str,
        payload: &[u8],
        headers: &NatsHeaders,
    ) -> Result<(), NatsError> {
        let header_block = headers.encode();
        let header_len = header_block.len();
        let total_len = header_len + payload.len();
        let command = format!("HPUB {subject} {header_len} {total_len}\r\n");
        let mut guard = self.inner.lock().await;
        guard.write_all(command.as_bytes()).await?;
        guard.write_all(&header_block).await?;
        guard.write_all(payload).await?;
        guard.write_all(b"\r\n").await?;
        guard.flush().await?;
        Ok(())
    }
}

pub struct NatsEventPublisher {
    writer: Arc<Writer>,
}

impl NatsEventPublisher {
    pub fn new(writer: Arc<Writer>) -> Self {
        Self { writer }
    }
}

#[async_trait::async_trait]
impl crate::events::EventPublisher for NatsEventPublisher {
    async fn publish(
        &self,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), crate::events::PublishError> {
        info!(
            subject = %subject,
            size = payload.len(),
            "publishing event to nats"
        );
        let mut headers = NatsHeaders::default();
        telemetry_nats::inject(&mut headers);
        self.writer
            .publish(subject, payload, &headers)
            .await
            .map_err(|err| crate::events::PublishError::Dispatch(err.to_string()))
    }
}

pub async fn connect(
    options: &NatsOptions,
) -> Result<(Arc<Writer>, ReadHalf<DynStream>), NatsError> {
    let url = Url::parse(&options.url)?;
    let host = url
        .host_str()
        .ok_or_else(|| NatsError::Protocol("missing host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| NatsError::Protocol("missing port".into()))?;
    let addr = format!("{host}:{port}");

    let stream = TcpStream::connect(addr).await?;

    let requires_tls = url.scheme() == "tls" || options.tls_domain.is_some();
    let stream: DynStream = if requires_tls {
        let mut root_store = rustls::RootCertStore::empty();
        let anchors = TLS_SERVER_ROOTS.iter().map(|anchor| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                anchor.subject,
                anchor.spki,
                anchor.name_constraints,
            )
        });
        root_store.add_trust_anchors(anchors);
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let domain = options.tls_domain.as_deref().unwrap_or(host);
        let server_name = rustls::ServerName::try_from(domain)
            .map_err(|_| NatsError::Protocol("invalid tls domain".into()))?;
        let tls_stream = connector.connect(server_name, stream).await?;
        Box::pin(tls_stream)
    } else {
        Box::pin(stream)
    };

    let (reader, writer) = io::split(stream);
    let writer = Arc::new(Writer {
        inner: Mutex::new(writer),
    });

    let mut reader = BufReader::new(reader);
    let mut info_line = String::new();
    reader.read_line(&mut info_line).await?;
    if !info_line.starts_with("INFO") {
        return Err(NatsError::Protocol("expected INFO line".into()));
    }

    let connect_payload = serde_json::json!({
        "verbose": false,
        "pedantic": false,
        "tls_required": requires_tls,
        "name": "greentic-oauth",
        "lang": "rust",
        "version": "0.1"
    });
    writer
        .write_command(&format!("CONNECT {connect_payload}\r\n"))
        .await?;
    writer.write_command("PING\r\n").await?;

    Ok((writer, reader.into_inner()))
}

pub async fn spawn_request_listener<S>(
    writer: Arc<Writer>,
    reader: ReadHalf<DynStream>,
    ctx: SharedContext<S>,
) -> Result<JoinHandle<()>, NatsError>
where
    S: SecretsManager + 'static,
{
    writer.write_command("SUB oauth.> 1\r\n").await?;
    info!(subject = "oauth.>", "subscribed to NATS subjects");
    writer.write_command("PING\r\n").await?;

    let reader = BufReader::new(reader);
    let writer_clone = writer.clone();

    let handle = tokio::spawn(async move {
        if let Err(err) = read_loop(writer_clone, reader, ctx).await {
            warn!("nats read loop terminated: {err}");
        }
    });

    Ok(handle)
}

async fn read_loop<S>(
    writer: Arc<Writer>,
    mut reader: BufReader<ReadHalf<DynStream>>,
    ctx: SharedContext<S>,
) -> Result<(), NatsError>
where
    S: SecretsManager + 'static,
{
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        if line.starts_with("MSG") {
            handle_msg_line(&line, &mut reader, &writer, &ctx).await?;
        } else if line.starts_with("PING") {
            writer.write_command("PONG\r\n").await?;
        }
    }
    Ok(())
}

async fn handle_msg_line<S>(
    line: &str,
    reader: &mut BufReader<ReadHalf<DynStream>>,
    writer: &Arc<Writer>,
    ctx: &SharedContext<S>,
) -> Result<(), NatsError>
where
    S: SecretsManager + 'static,
{
    let mut headers = NatsHeaders::default();
    let (subject, reply, payload) = if line.starts_with("HMSG") {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() != 5 && tokens.len() != 6 {
            return Err(NatsError::Protocol("malformed HMSG frame".into()));
        }
        let subject = tokens
            .get(1)
            .ok_or_else(|| NatsError::Protocol("missing subject".into()))?
            .to_string();
        let reply = if tokens.len() == 6 {
            Some(tokens[3].to_string())
        } else {
            None
        };
        let hdr_len_idx = if tokens.len() == 6 { 4 } else { 3 };
        let total_len_idx = hdr_len_idx + 1;
        let header_len = tokens[hdr_len_idx]
            .parse::<usize>()
            .map_err(|_| NatsError::Protocol("invalid header length".into()))?;
        let total_len = tokens[total_len_idx]
            .parse::<usize>()
            .map_err(|_| NatsError::Protocol("invalid message length".into()))?;
        if total_len < header_len {
            return Err(NatsError::Protocol(
                "total length smaller than header".into(),
            ));
        }
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes).await?;
        headers = NatsHeaders::from_bytes(&header_bytes).map_err(NatsError::Protocol)?;
        let payload_len = total_len - header_len;
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        (subject, reply, payload)
    } else {
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // MSG
        let subject = parts
            .next()
            .ok_or_else(|| NatsError::Protocol("missing subject".into()))?
            .to_string();
        let _sid = parts
            .next()
            .ok_or_else(|| NatsError::Protocol("missing sid".into()))?;

        let third = parts
            .next()
            .ok_or_else(|| NatsError::Protocol("missing size".into()))?;
        let (reply, size_token) = match parts.next() {
            Some(fourth) => (Some(third.to_string()), fourth),
            None => (None, third),
        };
        let size = size_token
            .parse::<usize>()
            .map_err(|_| NatsError::Protocol("invalid size".into()))?;
        let mut payload = vec![0u8; size];
        reader.read_exact(&mut payload).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        (subject, reply, payload)
    };

    let reply = reply.ok_or_else(|| NatsError::InvalidRequest("request missing reply".into()))?;

    let span = tracing::info_span!("nats.handle", subject = %subject, inbox = %reply);
    let _entered = span.enter();
    telemetry_nats::extract(&headers);

    info!(subject = %subject, size = payload.len(), headers = headers.len(), "received NATS oauth request");

    let response = process_request(&subject, &payload, ctx).await?;
    let mut response_headers = NatsHeaders::default();
    telemetry_nats::inject(&mut response_headers);
    writer.publish(&reply, &response, &response_headers).await?;
    info!(subject = %reply, size = response.len(), "sent NATS oauth response");
    Ok(())
}

async fn process_request<S>(
    subject: &str,
    payload: &[u8],
    ctx: &SharedContext<S>,
) -> Result<Vec<u8>, NatsError>
where
    S: SecretsManager + 'static,
{
    let parts: Vec<&str> = subject.split('.').collect();
    if parts.is_empty() || parts[0] != "oauth" {
        return Err(NatsError::InvalidRequest(format!(
            "subject `{subject}` not supported"
        )));
    }

    match parts.get(1).copied() {
        Some("req") => handle_start_request(&parts, payload, ctx).await,
        Some("token") if parts.get(2) == Some(&"get") => handle_token_get(payload, ctx).await,
        Some("fetch") if parts.get(2) == Some(&"signed") => handle_signed_fetch(payload, ctx).await,
        _ => Err(NatsError::InvalidRequest(format!(
            "subject `{subject}` not supported"
        ))),
    }
}
