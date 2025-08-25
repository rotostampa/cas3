use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::put,
    Router,
};
use dotenv::dotenv;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sha256: String,
    content_length: u64,
    exp: usize, // Expiration time
}

#[derive(Clone)]
struct AppState {
    s3_client: S3Client,
    jwt_secret: String,
    s3_bucket: String,
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Invalid JWT token: {0}")]
    InvalidToken(String),
    #[error("S3 error: {0}")]
    S3Error(String),
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::S3Error(msg) => (StatusCode::BAD_GATEWAY, msg),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        error!("Request failed: {}", error_message);
        (status, error_message).into_response()
    }
}

async fn upload_handler(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<impl IntoResponse, AppError> {
    // Decode and validate JWT
    let claims = validate_jwt(&token, &state.jwt_secret)?;
    info!(
        "Processing upload for SHA256: {}, expected length: {}",
        claims.sha256, claims.content_length
    );

    // Convert axum body to bytes first, then to ByteStream
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read body: {}", e)))?;
    let byte_stream = ByteStream::from(body_bytes.to_vec());

    // Use SHA256 from JWT as the S3 key
    let s3_key = &claims.sha256;

    // Create S3 PUT request
    let mut put_object = state
        .s3_client
        .put_object()
        .bucket(&state.s3_bucket)
        .key(s3_key)
        .body(byte_stream)
        .content_length(claims.content_length as i64)
        .checksum_sha256(&claims.sha256); // This makes S3 verify the SHA256

    // Forward relevant headers to S3
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            put_object = put_object.content_type(ct);
        }
    }

    // Execute S3 upload - S3 will verify the SHA256
    info!("Forwarding request to S3 with key: {}", s3_key);
    let result = put_object
        .send()
        .await
        .map_err(|e| AppError::S3Error(format!("S3 upload failed: {}", e)))?;

    info!("Successfully uploaded to S3 with key: {}", s3_key);

    // Return S3 response information
    let mut response_headers = HeaderMap::new();

    if let Some(etag) = result.e_tag() {
        response_headers.insert("etag", etag.parse().unwrap());
    }

    if let Some(version_id) = result.version_id() {
        response_headers.insert("x-amz-version-id", version_id.parse().unwrap());
    }

    // Return successful response similar to what S3 would return
    Ok((StatusCode::OK, response_headers, ""))
}

fn validate_jwt(token: &str, secret: &str) -> Result<Claims, AppError> {
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(token, &key, &validation)
        .map_err(|e| AppError::InvalidToken(e.to_string()))?;

    Ok(token_data.claims)
}

async fn health_check() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file
    dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration from environment
    let jwt_secret =
        env::var("JWT_SECRET").context("JWT_SECRET environment variable is required")?;

    let s3_bucket = env::var("S3_BUCKET").context("S3_BUCKET environment variable is required")?;

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    // Initialize AWS S3 client
    info!("Initializing AWS S3 client...");
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let s3_client = S3Client::new(&config);

    info!("S3 bucket: {}", s3_bucket);

    // Create application state
    let app_state = AppState {
        s3_client,
        jwt_secret,
        s3_bucket,
    };

    // Build our application with routes
    let app = Router::new()
        .route("/upload/{token}", put(upload_handler))
        .route("/health", axum::routing::get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // Start server
    info!("Starting server on {}", bind_addr);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    info!("CAS3 proxy server listening on {}", bind_addr);
    info!("Upload endpoint: PUT /upload/{{jwt_token}}");
    info!("Health check: GET /health");

    axum::serve(listener, app).await.context("Server failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_jwt_validation() {
        let secret = "test_secret";
        let claims = Claims {
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), // SHA256 of empty string
            content_length: 0,
            exp: (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap();

        let decoded_claims = validate_jwt(&token, secret).unwrap();
        assert_eq!(
            decoded_claims.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(decoded_claims.content_length, 0);
    }

    #[test]
    fn test_invalid_jwt() {
        let result = validate_jwt("invalid_token", "secret");
        assert!(matches!(result, Err(AppError::InvalidToken(_))));
    }

    #[test]
    fn test_expired_jwt() {
        let secret = "test_secret";
        let claims = Claims {
            sha256: "abc123".to_string(),
            content_length: 1024,
            exp: 1000000000, // Expired timestamp
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(matches!(result, Err(AppError::InvalidToken(_))));
    }
}
