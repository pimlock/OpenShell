// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use openshell_core::extension_protocol::{
    ExtensionFamily, http_hooks_middleware_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{
    HttpRequestHookResultStream, HttpResponseHookResultStream, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_hooks_server::{HttpHooks, HttpHooksServer};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Finding, HeaderMutation, HttpBodyMode, HttpContinue, HttpDuplexMode, HttpFinish, HttpInspect,
    HttpOutputChunk, HttpOutputStart, HttpPreflightResult, HttpRequestEvaluation,
    HttpRequestHookEvent, HttpRequestHookResult, HttpRequestPreflightHead, HttpRequestResult,
    HttpResponseHookEvent, MiddlewareBinding, MiddlewareDescribeRequest, MiddlewareDiagnostics,
    MiddlewareManifest, RemoveHeader, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent, header_mutation,
    http_inspect, http_preflight_result, http_request_hook_event, http_request_hook_result,
};
use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, MAX_EXTENSION_TOKEN_TTL,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::signer::{GitSigner, SignControl};

const MANIFEST_NAME: &str = "example/git-commit-signing";
const OPERATION: SupervisorMiddlewareOperation = SupervisorMiddlewareOperation::HttpRequest;
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_UNIT_BYTES: usize = 64 * 1024;
const JWT_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Parser)]
#[command(about = "Sign commits in Git smart-HTTP pushes outside an OpenShell sandbox")]
struct Cli {
    /// Address on which to serve authenticated TLS gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,

    /// Local SSH private key used by ssh-keygen. This path is never sent to the sandbox.
    #[arg(long)]
    signing_key: PathBuf,

    /// PEM certificate presented by this middleware service.
    #[arg(long)]
    tls_cert: PathBuf,

    /// PEM private key for the middleware TLS certificate.
    #[arg(long)]
    tls_key: PathBuf,

    /// PEM Ed25519 public key used to verify OpenShell extension JWTs.
    #[arg(long)]
    extension_public_key: PathBuf,

    /// Gateway ID expected in extension-token issuer claims.
    #[arg(long)]
    expected_gateway_id: String,

    /// Exact extension JWT audience configured for this registration.
    #[arg(long)]
    audience: String,

    /// Maximum number of concurrent Git rewrite workers.
    #[arg(long, default_value_t = 2)]
    max_concurrent_signings: usize,

    /// Total deadline for fetch, rewrite, signing, and pack generation.
    #[arg(long, default_value_t = 25)]
    signing_timeout_seconds: u64,
}

struct ExtensionAuth {
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl ExtensionAuth {
    fn new(public_key_pem: &[u8], gateway_id: &str, audience: String) -> Result<Self, String> {
        if gateway_id.is_empty() || audience.is_empty() {
            return Err("expected gateway ID and audience must be nonempty".into());
        }
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|error| format!("invalid extension public key: {error}"))?;
        Ok(Self {
            decoding_key,
            issuer: format!("openshell-gateway:{gateway_id}"),
            audience,
        })
    }

    fn authenticate<T>(
        &self,
        request: &Request<T>,
        required_caller: Option<ExtensionCallerKind>,
    ) -> Result<(), Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("extension bearer token is required"))?;
        let header = decode_header(authorization)
            .map_err(|_| Status::unauthenticated("extension bearer token is invalid"))?;
        if header.alg != Algorithm::EdDSA
            || header.typ.as_deref() != Some(EXTENSION_JWT_TYP)
            || header.kid.as_deref().is_none_or(str::is_empty)
        {
            return Err(Status::unauthenticated(
                "extension bearer token header is invalid",
            ));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp", "jti"]);
        let claims = decode::<ExtensionJwtClaims>(authorization, &self.decoding_key, &validation)
            .map_err(|_| Status::unauthenticated("extension bearer token is invalid"))?
            .claims;
        if claims.jti.is_empty()
            || claims.iat < 0
            || claims.exp <= claims.iat
            || u64::try_from(claims.exp - claims.iat)
                .ok()
                .is_none_or(|ttl| ttl > MAX_EXTENSION_TOKEN_TTL.as_secs())
        {
            return Err(Status::unauthenticated(
                "extension bearer token lifetime is invalid",
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock is before the Unix epoch"))?
            .as_secs() as i64;
        if claims.iat > now.saturating_add(JWT_CLOCK_SKEW_SECONDS) {
            return Err(Status::unauthenticated(
                "extension bearer token issue time is invalid",
            ));
        }
        if required_caller.is_some_and(|required| claims.caller_kind != required) {
            return Err(Status::permission_denied(
                "extension caller kind is not authorized for this RPC",
            ));
        }
        match claims.caller_kind {
            ExtensionCallerKind::Gateway
                if claims.sandbox_id.is_none() && claims.sub == self.issuer => {}
            ExtensionCallerKind::Supervisor => {
                let sandbox_id = claims.sandbox_id.as_deref().filter(|id| !id.is_empty());
                if sandbox_id
                    .is_none_or(|id| claims.sub != format!("spiffe://openshell/sandbox/{id}"))
                {
                    return Err(Status::permission_denied(
                        "extension supervisor identity is invalid",
                    ));
                }
            }
            _ => {
                return Err(Status::permission_denied(
                    "extension gateway identity is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct GitSigningMiddleware {
    signer: Arc<GitSigner>,
    auth: Arc<ExtensionAuth>,
    signing_slots: Arc<tokio::sync::Semaphore>,
    signing_timeout: Duration,
    expected_audience: String,
}

impl GitSigningMiddleware {
    fn new(
        signing_key: PathBuf,
        max_concurrent_signings: usize,
        signing_timeout: Duration,
        auth: ExtensionAuth,
    ) -> Result<Self, String> {
        if max_concurrent_signings == 0 {
            return Err("max concurrent signings must be positive".into());
        }
        Ok(Self {
            signer: Arc::new(GitSigner::new(signing_key)?),
            expected_audience: auth.audience.clone(),
            auth: Arc::new(auth),
            signing_slots: Arc::new(tokio::sync::Semaphore::new(max_concurrent_signings)),
            signing_timeout,
        })
    }

    #[cfg(test)]
    fn new_for_test(signing_key: PathBuf) -> Result<Self, String> {
        Ok(Self {
            signer: Arc::new(GitSigner::new(signing_key)?),
            auth: Arc::new(ExtensionAuth {
                decoding_key: DecodingKey::from_secret(b"unused-test-key"),
                issuer: "openshell-gateway:test".into(),
                audience: "urn:openshell:extension:test:git-signing".into(),
            }),
            signing_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            signing_timeout: Duration::from_secs(60),
            expected_audience: "urn:openshell:extension:test:git-signing".into(),
        })
    }

    fn request_stream<S>(&self, events: S) -> HttpRequestHookResultStream
    where
        S: tokio_stream::Stream<Item = Result<HttpRequestHookEvent, Status>>
            + Send
            + Unpin
            + 'static,
    {
        let middleware = self.clone();
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let result = middleware.sign_stream(events, &sender).await;
            if let Err(error) = result {
                let _ = sender.send(Err(error)).await;
            }
        });
        Box::pin(ReceiverStream::new(receiver))
    }

    async fn sign_stream<S>(&self, mut events: S, sender: &ResultSender) -> Result<(), Status>
    where
        S: tokio_stream::Stream<Item = Result<HttpRequestHookEvent, Status>> + Unpin,
    {
        use http_request_hook_event::Event;
        let preflight = match next_event(&mut events, sender).await? {
            Event::Preflight(preflight) => preflight,
            _ => return Err(Status::failed_precondition("expected request preflight")),
        };
        let Some(request) = preflight.request.as_ref() else {
            return Err(Status::invalid_argument("request head is required"));
        };
        if !is_receive_pack_request(request) {
            send(
                sender,
                http_request_hook_result::Result::PreflightResult(HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                        HttpContinue {},
                    )),
                    ..Default::default()
                }),
            )
            .await?;
            return Ok(());
        }
        let target = request
            .target
            .as_ref()
            .expect("selected request has a target");
        let upstream_url = github_upstream_url(target)?;
        let limits = preflight
            .limits
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("body limits are required"))?;
        if preflight.phase != PHASE as i32
            || !preflight
                .permitted_body_modes
                .contains(&(HttpBodyMode::Duplex as i32))
            || limits.max_chunk_bytes == 0
        {
            return Err(Status::failed_precondition(
                "Git signing requires request DUPLEX mode",
            ));
        }
        let unit_bytes = limits.max_chunk_bytes.min(MAX_UNIT_BYTES as u64) as usize;
        let body_limit = limits
            .max_output_body_bytes
            .unwrap_or(MAX_PUSH_BYTES)
            .min(MAX_PUSH_BYTES);
        if preflight
            .declared_body_bytes
            .is_some_and(|bytes| bytes > body_limit)
        {
            return Err(Status::resource_exhausted(
                "Git signing request exceeds storage limit",
            ));
        }
        // Hold the worker permit while receiving input to bound temporary storage.
        let permit = tokio::select! {
            permit = Arc::clone(&self.signing_slots).acquire_owned() => permit.map_err(|_| Status::unavailable("Git signer is shutting down"))?,
            () = sender.closed() => return Err(Status::cancelled("Git signing request was cancelled")),
        };
        let file = tempfile::tempfile().map_err(|_| {
            Status::resource_exhausted("Git signing temporary storage is unavailable")
        })?;
        let mut input = tokio::fs::File::from_std(file);
        send(
            sender,
            http_request_hook_result::Result::PreflightResult(HttpPreflightResult {
                decision: Some(http_preflight_result::Decision::Inspect(HttpInspect {
                    mode: Some(http_inspect::Mode::Duplex(HttpDuplexMode {})),
                })),
                ..Default::default()
            }),
        )
        .await?;
        if !matches!(next_event(&mut events, sender).await?, Event::Begin(_)) {
            return Err(Status::failed_precondition(
                "expected begin before request body",
            ));
        }
        let mut input_bytes = 0u64;
        loop {
            match next_event(&mut events, sender).await? {
                Event::InputChunk(chunk) => {
                    input_bytes = input_bytes.saturating_add(chunk.data.len() as u64);
                    if chunk.data.is_empty()
                        || chunk.data.len() as u64 > limits.max_chunk_bytes
                        || input_bytes > body_limit
                    {
                        return Err(Status::resource_exhausted(
                            "Git signing request exceeds storage or chunk limit",
                        ));
                    }
                    input.write_all(&chunk.data).await.map_err(|_| {
                        Status::resource_exhausted("Git signing storage write failed")
                    })?;
                }
                Event::InputEnd(end) => {
                    if !end.trailers.is_empty() {
                        return Err(Status::invalid_argument(
                            "Git signing does not support request trailers",
                        ));
                    }
                    break;
                }
                _ => {
                    return Err(Status::failed_precondition(
                        "expected body input or input_end",
                    ));
                }
            }
        }
        finish_signing(
            Arc::clone(&self.signer),
            SigningRequest {
                input,
                upstream_url,
                request_id: preflight
                    .context
                    .map(|context| context.request_id)
                    .unwrap_or_default(),
                limits: OutputLimits {
                    body_bytes: body_limit,
                    unit_bytes,
                },
            },
            permit,
            self.signing_timeout,
            sender,
        )
        .await
    }
}

const MAX_PUSH_BYTES: u64 = 256 * 1024 * 1024;
type ResultSender = tokio::sync::mpsc::Sender<Result<HttpRequestHookResult, Status>>;

async fn next_event<S>(
    events: &mut S,
    sender: &ResultSender,
) -> Result<http_request_hook_event::Event, Status>
where
    S: tokio_stream::Stream<Item = Result<HttpRequestHookEvent, Status>> + Unpin,
{
    tokio::select! {
        event = events.next() => event.ok_or_else(|| Status::cancelled("request input closed"))??.event.ok_or_else(|| Status::invalid_argument("request event is required")),
        () = sender.closed() => Err(Status::cancelled("Git signing request was cancelled")),
    }
}

async fn send(
    sender: &ResultSender,
    result: http_request_hook_result::Result,
) -> Result<(), Status> {
    sender
        .send(Ok(HttpRequestHookResult {
            result: Some(result),
        }))
        .await
        .map_err(|_| Status::cancelled("Git signing request was cancelled"))
}

#[derive(Clone, Copy)]
struct OutputLimits {
    body_bytes: u64,
    unit_bytes: usize,
}

struct SigningRequest {
    input: tokio::fs::File,
    upstream_url: String,
    request_id: String,
    limits: OutputLimits,
}

#[tonic::async_trait]
impl SupervisorMiddleware for GitSigningMiddleware {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        self.auth.authenticate(&request, None)?;
        let manifest = MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: OPERATION as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_UNIT_BYTES as u64,
                request_timeout: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
            }],
            expected_audience: self.expected_audience.clone(),
            extension: Some(http_hooks_middleware_metadata(
                MANIFEST_NAME,
                openshell_core::VERSION,
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Gateway))?;
        let request = request.into_inner();
        let unknown = request
            .config
            .as_ref()
            .and_then(|config| config.fields.keys().next())
            .cloned();
        Ok(Response::new(match unknown {
            None => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Some(field) => ValidateConfigResponse {
                valid: false,
                reason: format!("unsupported config field '{field}'"),
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        _request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented(
            "Git signing implements HTTP hooks only",
        ))
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Supervisor))?;
        Err(Status::unimplemented(
            "WebSocket middleware is not supported",
        ))
    }
}

#[tonic::async_trait]
impl HttpHooks for GitSigningMiddleware {
    type EvaluateRequestStream = HttpRequestHookResultStream;
    type EvaluateResponseStream = HttpResponseHookResultStream;

    async fn evaluate_request(
        &self,
        request: Request<tonic::Streaming<HttpRequestHookEvent>>,
    ) -> Result<Response<Self::EvaluateRequestStream>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Supervisor))?;
        Ok(Response::new(self.request_stream(request.into_inner())))
    }

    async fn evaluate_response(
        &self,
        _request: Request<tonic::Streaming<HttpResponseHookEvent>>,
    ) -> Result<Response<Self::EvaluateResponseStream>, Status> {
        Err(Status::unimplemented(
            "response middleware is not supported",
        ))
    }
}

async fn finish_signing(
    signer: Arc<GitSigner>,
    request: SigningRequest,
    _permit: tokio::sync::OwnedSemaphorePermit,
    signing_timeout: Duration,
    sender: &ResultSender,
) -> Result<(), Status> {
    let SigningRequest {
        mut input,
        upstream_url,
        request_id,
        limits,
    } = request;
    input
        .flush()
        .await
        .map_err(|_| Status::internal("Git signing temporary storage flush failed"))?;
    let input = input.into_std().await;
    let log_upstream = upstream_url.clone();
    let log_request_id = request_id.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let control = SignControl::new(Arc::clone(&cancelled), Instant::now() + signing_timeout);
    let mut worker = tokio::task::spawn_blocking(move || {
        signer.sign_receive_pack(input, Some(&upstream_url), &control)
    });
    let signed = tokio::select! {
        result = &mut worker => {
            result.map_err(|_| Status::internal("Git signing worker failed"))?
        }
        () = sender.closed() => {
            cancelled.store(true, Ordering::Release);
            let _ = worker.await;
            return Err(Status::cancelled("Git signing request was cancelled"));
        }
        () = tokio::time::sleep(signing_timeout) => {
            cancelled.store(true, Ordering::Release);
            let _ = worker.await;
            return Err(Status::deadline_exceeded("Git signing deadline exceeded"));
        }
    }
    .map_err(|error| {
        let status = if error.is_cancelled() {
            Status::cancelled("Git signing request was cancelled")
        } else if error.is_timed_out() {
            Status::deadline_exceeded("Git signing deadline exceeded")
        } else {
            Status::failed_precondition(error.public_message())
        };
        warn!(
            request_id = log_request_id,
            upstream = %log_upstream,
            category = if error.is_cancelled() { "cancelled" } else if error.is_timed_out() { "timeout" } else { "invalid_push" },
            "outgoing Git push could not be signed"
        );
        status
    })?;

    if signed.body_len > limits.body_bytes {
        return Err(Status::resource_exhausted(
            "signed Git request exceeds deferred storage limit",
        ));
    }

    let signed_commits = signed.signed_commits;
    let header_mutations = [
        "etag",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "signature",
        "signature-input",
    ]
    .into_iter()
    .map(|name| HeaderMutation {
        operation: Some(header_mutation::Operation::Remove(RemoveHeader {
            name: name.into(),
        })),
    })
    .collect();
    send(
        sender,
        http_request_hook_result::Result::OutputStart(HttpOutputStart {
            output_body_bytes: Some(signed.body_len),
            header_mutations,
        }),
    )
    .await?;
    let mut body = tokio::fs::File::from_std(signed.body);
    let mut chunk = vec![0; limits.unit_bytes];
    loop {
        let read = body
            .read(&mut chunk)
            .await
            .map_err(|_| Status::internal("signed Git storage read failed"))?;
        if read == 0 {
            break;
        }
        send(
            sender,
            http_request_hook_result::Result::OutputChunk(HttpOutputChunk {
                data: chunk[..read].to_vec(),
            }),
        )
        .await?;
    }
    send(
        sender,
        http_request_hook_result::Result::Finish(HttpFinish {
            diagnostics: Some(MiddlewareDiagnostics {
                reason_code: "git_commits_signed".into(),
                findings: vec![Finding {
                    r#type: "git.commits_signed".into(),
                    label: "Git commits signed".into(),
                    count: signed_commits,
                    confidence: "high".into(),
                    severity: "informational".into(),
                }],
                metadata: HashMap::from([(
                    "signed_commit_count".into(),
                    signed_commits.to_string(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await?;
    info!(
        request_id,
        upstream = %log_upstream,
        signed_commits,
        "signed outgoing Git push"
    );
    Ok(())
}

fn github_upstream_url(
    target: &openshell_core::proto::HttpRequestTarget,
) -> Result<String, Status> {
    if target.scheme != "https" || target.host != "github.com" || target.port != 443 {
        return Err(Status::invalid_argument(
            "prototype supports HTTPS pushes to github.com only",
        ));
    }
    let repository_path = target
        .path
        .strip_suffix("/git-receive-pack")
        .ok_or_else(|| Status::invalid_argument("invalid Git receive-pack path"))?;
    let segments = repository_path
        .strip_prefix('/')
        .and_then(|path| path.strip_suffix(".git"))
        .map(|path| path.split('/').collect::<Vec<_>>())
        .ok_or_else(|| Status::invalid_argument("invalid GitHub repository path"))?;
    if segments.len() != 2
        || segments.iter().any(|segment| {
            matches!(*segment, "" | "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(Status::invalid_argument("invalid GitHub repository path"));
    }
    Ok(format!("https://github.com{repository_path}"))
}

fn is_receive_pack_request(request: &HttpRequestPreflightHead) -> bool {
    let Some(target) = request.target.as_ref() else {
        return false;
    };
    target.method == "POST"
        && target.path.ends_with("/git-receive-pack")
        && request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header
                    .value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/x-git-receive-pack-request")
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    if cli.signing_timeout_seconds == 0 {
        return Err("signing timeout must be positive".into());
    }
    let tls_cert = std::fs::read(&cli.tls_cert)?;
    let tls_key = std::fs::read(&cli.tls_key)?;
    let extension_public_key = std::fs::read(&cli.extension_public_key)?;
    let auth = ExtensionAuth::new(
        &extension_public_key,
        &cli.expected_gateway_id,
        cli.audience,
    )
    .map_err(|error| format!("invalid extension authentication configuration: {error}"))?;
    let middleware = GitSigningMiddleware::new(
        cli.signing_key,
        cli.max_concurrent_signings,
        Duration::from_secs(cli.signing_timeout_seconds),
        auth,
    )
    .map_err(|error| format!("invalid signing configuration: {error}"))?;
    info!(bind = %cli.bind, "starting Git commit signing middleware");
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(tls_cert, tls_key)))?
        .add_service(SupervisorMiddlewareServer::new(middleware.clone()))
        .add_service(HttpHooksServer::new(middleware))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use openshell_core::proto::HttpRequestHookPreflight;

    const TEST_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAR9CeOXmiSU6YscHZWTYbW7DUc5uhdO3/OeXZg3j1+u
-----END PRIVATE KEY-----
"#;
    const TEST_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuEbM0q6xP8hFxwY5kd/fD/mwr3ZpA/T7zhx6TN0DKMM=
-----END PUBLIC KEY-----
"#;

    fn authenticated_request(claims: ExtensionJwtClaims) -> Request<()> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(EXTENSION_JWT_TYP.into());
        header.kid = Some("test-key".into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(TEST_PRIVATE_KEY).unwrap(),
        )
        .unwrap();
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    fn test_claims(caller_kind: ExtensionCallerKind) -> ExtensionJwtClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (sub, sandbox_id) = match caller_kind {
            ExtensionCallerKind::Gateway => ("openshell-gateway:test".into(), None),
            ExtensionCallerKind::Supervisor => (
                "spiffe://openshell/sandbox/sandbox-test".into(),
                Some("sandbox-test".into()),
            ),
        };
        ExtensionJwtClaims {
            iss: "openshell-gateway:test".into(),
            aud: "urn:openshell:extension:test:git-signing".into(),
            sub,
            iat: now,
            exp: now + 300,
            jti: "unique-test-token".into(),
            caller_kind,
            sandbox_id,
        }
    }

    #[test]
    fn extension_auth_enforces_rpc_caller_kind() {
        let auth = ExtensionAuth::new(
            TEST_PUBLIC_KEY,
            "test",
            "urn:openshell:extension:test:git-signing".into(),
        )
        .unwrap();

        assert!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Gateway)),
                Some(ExtensionCallerKind::Gateway),
            )
            .is_ok()
        );
        assert_eq!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Gateway)),
                Some(ExtensionCallerKind::Supervisor),
            )
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Supervisor)),
                Some(ExtensionCallerKind::Supervisor),
            )
            .is_ok()
        );
    }

    #[test]
    fn extension_auth_rejects_mismatched_supervisor_identity() {
        let auth = ExtensionAuth::new(
            TEST_PUBLIC_KEY,
            "test",
            "urn:openshell:extension:test:git-signing".into(),
        )
        .unwrap();
        let mut claims = test_claims(ExtensionCallerKind::Supervisor);
        claims.sub = "spiffe://openshell/sandbox/another-sandbox".into();

        assert_eq!(
            auth.authenticate(
                &authenticated_request(claims),
                Some(ExtensionCallerKind::Supervisor),
            )
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
    }

    pub(super) fn receive_pack_preflight() -> HttpRequestHookPreflight {
        HttpRequestHookPreflight {
            phase: PHASE as i32,
            request: Some(HttpRequestPreflightHead {
                target: Some(openshell_core::proto::HttpRequestTarget {
                    scheme: "https".into(),
                    host: "github.com".into(),
                    port: 443,
                    method: "POST".into(),
                    path: "/NVIDIA/OpenShell.git/git-receive-pack".into(),
                    ..Default::default()
                }),
                headers: vec![openshell_core::proto::HttpHeader {
                    name: "content-type".into(),
                    value: "application/x-git-receive-pack-request".into(),
                }],
            }),
            permitted_body_modes: vec![HttpBodyMode::Duplex as i32],
            limits: Some(openshell_core::proto::HttpBodyLimits {
                max_chunk_bytes: MAX_UNIT_BYTES as u64,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn recognizes_git_receive_pack_only() {
        let mut preflight = receive_pack_preflight();
        let request = preflight.request.as_mut().unwrap();
        assert!(is_receive_pack_request(request));
        request.target.as_mut().unwrap().path = "/NVIDIA/OpenShell.git/git-upload-pack".into();
        assert!(!is_receive_pack_request(request));
    }

    #[test]
    fn derives_a_bounded_github_upstream_url() {
        let mut target = receive_pack_preflight().request.unwrap().target.unwrap();
        assert_eq!(
            github_upstream_url(&target).unwrap(),
            "https://github.com/NVIDIA/OpenShell.git"
        );
        target.path = "/../repo.git/git-receive-pack".into();
        assert!(github_upstream_url(&target).is_err());
    }
    async fn preflight_result(
        preflight: HttpRequestHookPreflight,
    ) -> Result<HttpRequestHookResult, Status> {
        let key = tempfile::NamedTempFile::new().unwrap();
        let middleware = GitSigningMiddleware::new_for_test(key.path().to_path_buf()).unwrap();
        middleware
            .request_stream(tokio_stream::iter([Ok(HttpRequestHookEvent {
                event: Some(http_request_hook_event::Event::Preflight(preflight)),
            })]))
            .next()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn skips_fetches_but_refuses_uninspectable_pushes() {
        let mut fetch = receive_pack_preflight();
        fetch
            .request
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .path = "/NVIDIA/OpenShell.git/git-upload-pack".into();
        let result = preflight_result(fetch).await.unwrap();
        assert!(matches!(
            result.result,
            Some(http_request_hook_result::Result::PreflightResult(
                HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                    ..
                }
            ))
        ));
        let mut encoded_push = receive_pack_preflight();
        encoded_push.permitted_body_modes.clear();
        assert_eq!(
            preflight_result(encoded_push).await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn rejects_declared_pushes_above_route_limit() {
        let mut preflight = receive_pack_preflight();
        preflight.declared_body_bytes = Some(1025);
        preflight.limits.as_mut().unwrap().max_output_body_bytes = Some(1024);
        assert_eq!(
            preflight_result(preflight).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[tokio::test]
    async fn withholds_output_until_the_complete_push_arrives() {
        use http_request_hook_event::Event;
        let key = tempfile::NamedTempFile::new().unwrap();
        let middleware = GitSigningMiddleware::new_for_test(key.path().to_path_buf()).unwrap();
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let mut results = middleware.request_stream(ReceiverStream::new(receiver));
        sender
            .send(Ok(HttpRequestHookEvent {
                event: Some(Event::Preflight(receive_pack_preflight())),
            }))
            .await
            .unwrap();
        results.next().await.unwrap().unwrap();
        sender
            .send(Ok(HttpRequestHookEvent {
                event: Some(Event::Begin(openshell_core::proto::HttpBegin::default())),
            }))
            .await
            .unwrap();
        // More than the old unary cap, with no complete pack and no input_end.
        for _ in 0..65 {
            sender
                .send(Ok(HttpRequestHookEvent {
                    event: Some(Event::InputChunk(openshell_core::proto::HttpInputChunk {
                        data: vec![b'x'; MAX_UNIT_BYTES],
                    })),
                }))
                .await
                .unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), results.next())
                .await
                .is_err()
        );
        drop(sender);
        assert_eq!(
            results.next().await.unwrap().unwrap_err().code(),
            tonic::Code::Cancelled
        );
        assert!(results.next().await.is_none());
    }

    #[tokio::test]
    async fn rejects_trailers_and_missing_begin_without_output() {
        use http_request_hook_event::Event;
        for (begin, trailers) in [
            (false, Vec::new()),
            (
                true,
                vec![openshell_core::proto::HttpHeader {
                    name: "digest".into(),
                    value: "stale".into(),
                }],
            ),
        ] {
            let key = tempfile::NamedTempFile::new().unwrap();
            let middleware = GitSigningMiddleware::new_for_test(key.path().to_path_buf()).unwrap();
            let mut events = vec![Event::Preflight(receive_pack_preflight())];
            if begin {
                events.push(Event::Begin(openshell_core::proto::HttpBegin::default()));
            }
            events.push(Event::InputEnd(openshell_core::proto::HttpInputEnd {
                trailers,
            }));
            let mut results = middleware.request_stream(tokio_stream::iter(
                events
                    .into_iter()
                    .map(|event| Ok(HttpRequestHookEvent { event: Some(event) })),
            ));
            results.next().await.unwrap().unwrap();
            let error = results.next().await.unwrap().unwrap_err();
            assert_eq!(
                error.code(),
                if begin {
                    tonic::Code::InvalidArgument
                } else {
                    tonic::Code::FailedPrecondition
                }
            );
            assert!(results.next().await.is_none());
        }
    }
    #[tokio::test]
    async fn serves_http_hooks_over_authenticated_tls() {
        use openshell_core::proto::middleware::v1::http_hooks_client::HttpHooksClient;
        use tokio_stream::wrappers::TcpListenerStream;
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = certificate.cert.pem();
        let key = tempfile::NamedTempFile::new().unwrap();
        let auth = ExtensionAuth::new(
            TEST_PUBLIC_KEY,
            "test",
            "urn:openshell:extension:test:git-signing".into(),
        )
        .unwrap();
        let middleware =
            GitSigningMiddleware::new(key.path().to_path_buf(), 1, Duration::from_secs(10), auth)
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                    cert_pem.clone(),
                    certificate.signing_key.serialize_pem(),
                )))
                .unwrap()
                .add_service(SupervisorMiddlewareServer::new(middleware.clone()))
                .add_service(HttpHooksServer::new(middleware))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                }),
        );
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(cert_pem)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = HttpHooksClient::new(channel);
        let event = || {
            let mut preflight = receive_pack_preflight();
            preflight
                .request
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .method = "GET".into();
            HttpRequestHookEvent {
                event: Some(http_request_hook_event::Event::Preflight(preflight)),
            }
        };
        assert_eq!(
            client
                .evaluate_request(tokio_stream::iter([event()]))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let request = authenticated_request(test_claims(ExtensionCallerKind::Supervisor))
            .map(|_| tokio_stream::iter([event()]));
        let mut results = client.evaluate_request(request).await.unwrap().into_inner();
        assert!(matches!(
            results.message().await.unwrap().unwrap().result,
            Some(http_request_hook_result::Result::PreflightResult(
                HttpPreflightResult {
                    decision: Some(http_preflight_result::Decision::ContinueWithoutBody(_)),
                    ..
                }
            ))
        ));
        assert!(results.message().await.unwrap().is_none());
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
