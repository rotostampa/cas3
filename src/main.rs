use aws_config::BehaviorVersion;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use aws_smithy_types::body::SdkBody;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::put,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use dotenv::dotenv;
use futures_util::stream::{Stream, StreamExt};
use http_body_util::StreamBody;
use hyper::body::Frame;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sha256: String,
    content_length: i64,
    exp: usize, // Expiration time
}

#[derive(Clone)]
struct AppState {
    s3_client: S3Client,
    s3_bucket: String,
    jwt_secret: String,
    s3_key_prefix: String,
}

// A wrapper stream that implements Sync
struct SyncStream {
    rx: mpsc::Receiver<Result<Frame<bytes::Bytes>, std::io::Error>>,
}

impl Stream for SyncStream {
    type Item = Result<Frame<bytes::Bytes>, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

// Safety: We ensure the receiver is only used from one task at a time
unsafe impl Sync for SyncStream {}

async fn upload_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    // Decode and validate JWT
    let claims = match validate_jwt(&token, &state.jwt_secret) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    // Create a channel for streaming data
    let (tx, rx) = mpsc::channel::<Result<Frame<bytes::Bytes>, std::io::Error>>(16);

    // Spawn a task to read from the body and send to the channel
    let data_stream = body.into_data_stream();
    tokio::spawn(async move {
        let mut stream = data_stream;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        // Receiver dropped, stop sending
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::other(format!(
                            "Body stream error: {}",
                            e
                        ))))
                        .await;
                    break;
                }
            }
        }
    });

    // Create a stream from the receiver that implements Sync
    let sync_stream = SyncStream { rx };

    // Create StreamBody from our sync stream
    let stream_body = StreamBody::new(sync_stream);

    // Convert to SdkBody and ByteStream
    let sdk_body = SdkBody::from_body_1_x(stream_body);
    let byte_stream = ByteStream::new(sdk_body);

    // Convert hex SHA256 to base64 for S3 checksum header
    let sha256_bytes = match hex::decode(&claims.sha256) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Request failed: Invalid SHA256 hex: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid SHA256 hex in JWT: {}", e),
            )
                .into_response();
        }
    };

    // Create S3 PUT request
    let mut put_object = state
        .s3_client
        .put_object()
        .bucket(&state.s3_bucket)
        .key(format!("{}{}", state.s3_key_prefix, claims.sha256))
        .body(byte_stream)
        .content_length(claims.content_length) // Set content length from JWT to avoid chunked encoding
        .checksum_sha256(general_purpose::STANDARD.encode(&sha256_bytes)); // S3 expects base64-encoded checksum

    // Forward relevant headers to S3
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            put_object = put_object.content_type(ct);
        }
    }

    // Execute S3 upload - S3 will verify the SHA256

    match put_object.send().await {
        Ok(_result) => {
            // S3 upload successful, return 200 OK
            StatusCode::OK.into_response()
        }
        Err(e) => {
            // Extract HTTP status code and response body from S3 error
            match &e {
                SdkError::ServiceError(service_err) => {
                    let status_code = StatusCode::from_u16(service_err.raw().status().as_u16())
                        .unwrap_or(StatusCode::BAD_GATEWAY);

                    // Extract the raw response body bytes from S3
                    let response_body = match service_err.raw().body().bytes() {
                        Some(body_bytes) => body_bytes.to_vec(),
                        None => service_err.err().to_string().into_bytes(),
                    };

                    (status_code, response_body).into_response()
                }
                _ => {
                    let error_msg = format!("S3 request failed: {}", e);
                    (StatusCode::BAD_GATEWAY, error_msg).into_response()
                }
            }
        }
    }
}

fn validate_jwt(token: &str, secret: &str) -> Result<Claims, Response> {
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    match decode::<Claims>(token, &key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => {
            let error_message = format!("Invalid JWT token: {}", e);
            eprintln!("Request failed: {}", error_message);
            Err((StatusCode::UNAUTHORIZED, error_message).into_response())
        }
    }
}

async fn health_check() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenv().ok();

    // Load configuration from environment
    let jwt_secret = env::var("CAS3_JWT_SECRET")
        .map_err(|_| "CAS3_JWT_SECRET environment variable is required")?;

    let s3_bucket =
        env::var("CAS3_BUCKET").map_err(|_| "CAS3_BUCKET environment variable is required")?;

    let bind_addr = env::var("CAS3_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    let s3_key_prefix = env::var("CAS3_S3_KEY_PREFIX").unwrap_or_else(|_| "".to_string());

    // Initialize AWS S3 client
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let s3_client = S3Client::new(&config);

    // Create application state
    let app_state = AppState {
        s3_client,
        jwt_secret,
        s3_bucket,
        s3_key_prefix,
    };

    // Build our application with routes
    let app = Router::new()
        .route("/upload/{token}", put(upload_handler))
        .route("/health", axum::routing::get(health_check))
        .with_state(app_state);

    // Start server
    println!("Starting server on {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;

    println!("CAS3 proxy server listening on {}", bind_addr);
    println!("Upload endpoint: PUT /upload/{{jwt_token}}");
    println!("Health check: GET /health");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server failed: {}", e))?;

    Ok(())
}
