use aws_config::BehaviorVersion;
use aws_sdk_s3::error::SdkError;

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use aws_smithy_types::body::SdkBody;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::put,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use dotenv::dotenv;

use futures_util::stream::{Stream, StreamExt};
use http_body_util::StreamBody;
use hyper::body::Frame;
use infer;
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
struct ReceiverStream {
    receiver: mpsc::Receiver<Result<Frame<bytes::Bytes>, std::io::Error>>,
}

impl Stream for ReceiverStream {
    type Item = Result<Frame<bytes::Bytes>, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

async fn upload_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    // Decode and validate JWT - inlined validate_jwt function
    let claims = {
        let key = DecodingKey::from_secret(state.jwt_secret.as_ref());
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(&token, &key, &validation) {
            Ok(token_data) => token_data.claims,
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid JWT token: {}", e),
                )
                    .into_response();
            }
        }
    };

    // Convert hex SHA256 to base64 for S3 checksum header
    let sha256_bytes = match hex::decode(&claims.sha256) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid SHA256 hex in JWT: {}", e),
            )
                .into_response();
        }
    };

    // Get the first chunk to detect content type
    let mut data_stream = body.into_data_stream();
    let first_chunk = match data_stream.next().await {
        Some(Ok(bytes)) => bytes,
        Some(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Error reading request body: {}", e),
            )
                .into_response();
        }
        None => {
            return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
        }
    };

    // Always try to detect content type from first chunk (don't trust client)
    let detected_content_type = infer::get(&first_chunk).map(|kind| kind.mime_type().to_string());

    // Create a channel for streaming data
    let (sender, receiver) = mpsc::channel::<Result<Frame<bytes::Bytes>, std::io::Error>>(16);

    // Spawn a task to send the first chunk and then the rest of the stream
    tokio::spawn(async move {
        // Send the first chunk we already read
        if sender.send(Ok(Frame::data(first_chunk))).await.is_err() {
            return;
        }

        // Send the rest of the stream
        while let Some(chunk) = data_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if sender.send(Ok(Frame::data(bytes))).await.is_err() {
                        // Receiver dropped, stop sending
                        return;
                    }
                }
                _ => return,
            }
        }
    });

    // Create a stream from the receiver that implements Sync
    let request_stream = ReceiverStream { receiver };

    // Create StreamBody from our sync stream
    let request_body = StreamBody::new(request_stream);

    // Convert to SdkBody and ByteStream
    let request_bytes = ByteStream::new(SdkBody::from_body_1_x(request_body));

    // Create S3 PUT request
    let mut put_object = state
        .s3_client
        .put_object()
        .bucket(&state.s3_bucket)
        .key(format!("{}{}", state.s3_key_prefix, claims.sha256))
        .body(request_bytes)
        .content_length(claims.content_length) // Set content length from JWT to avoid chunked encoding
        .checksum_sha256(general_purpose::STANDARD.encode(&sha256_bytes)); // S3 expects base64-encoded checksum

    // Use auto-detected content-type, fallback to client header if detection fails
    if let Some(detected_ct) = detected_content_type {
        put_object = put_object.content_type(detected_ct);
    } else if let Some(content_type) = headers.get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            put_object = put_object.content_type(ct);
        }
    }

    // Execute S3 upload - S3 will verify the SHA256
    match put_object.send().await {
        Ok(_result) => {
            // S3 upload successful, get presigned URL for the object
            StatusCode::OK.into_response()
        }
        Err(SdkError::ServiceError(service_err)) => {
            let status_code = StatusCode::from_u16(service_err.raw().status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);

            // Extract the raw response body bytes from S3
            let response_body = match service_err.raw().body().bytes() {
                Some(body_bytes) => body_bytes.to_vec(),
                None => service_err.err().to_string().into_bytes(),
            };

            (status_code, response_body).into_response()
        }
        Err(e) => {
            let error_msg = format!("S3 request failed: {}", e);
            (StatusCode::BAD_GATEWAY, error_msg).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenv().ok();

    // Load configuration from environment
    let bind_addr = env::var("CAS3_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    // Initialize AWS S3 client
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

    // Build our application with routes
    let app = Router::new()
        .route("/upload/{token}", put(upload_handler))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .with_state(AppState {
            s3_client: S3Client::new(&config),
            jwt_secret: env::var("CAS3_JWT_SECRET")
                .map_err(|_| "CAS3_JWT_SECRET environment variable is required")?,
            s3_bucket: env::var("CAS3_BUCKET")
                .map_err(|_| "CAS3_BUCKET environment variable is required")?,
            s3_key_prefix: env::var("CAS3_S3_KEY_PREFIX").unwrap_or_else(|_| "".to_string()),
        });

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
