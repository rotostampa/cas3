# CAS3 – Content-Addressable Storage Proxy Server

CAS3 is a secure proxy server that provides content-addressable storage (CAS) for files in Amazon S3. It uses JWT authentication to ensure that only authorized uploads are allowed, and stores files based on their SHA-256 hash.

## Features

- **Content-Addressable Storage**: Files are stored by their SHA-256 hash, ensuring deduplication
- **JWT Authentication**: Secure uploads using JWT tokens containing file metadata
- **S3 Backend**: Reliable storage using Amazon S3
- **Hash Verification**: Ensures data integrity by verifying SHA-256 hashes
- **Size Validation**: Validates content length to prevent abuse

## How It Works

1. Client calculates the SHA-256 hash of the file to upload
2. Client creates a JWT token containing the hash and file size
3. Client sends the file to the server with the JWT token in the URL
4. Server validates the JWT token and verifies the file matches the claims
5. Server stores the file in S3 using the SHA-256 hash as the key

## Environment Configuration

Create a `.env` file in the project root with the following variables. The server supports both `.env` files and system environment variables:

```env
# Required: JWT secret for token validation
CAS3_JWT_SECRET=your-secret-key-here

# Required: S3 bucket name for storing files
CAS3_BUCKET=your-bucket-name

# Optional: Server bind address (default: 0.0.0.0:3000)
CAS3_BIND_ADDR=0.0.0.0:3000

# Optional: S3 key prefix (default: empty string)
# Example: "hashstore/" will store files as "hashstore/<sha256>"
CAS3_S3_KEY_PREFIX=

# AWS Configuration (standard AWS SDK environment variables)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### Environment Variables

- `CAS3_JWT_SECRET`: Secret key used to sign and verify JWT tokens (required)
- `CAS3_BUCKET`: Name of the S3 bucket to store files (required)
- `CAS3_BIND_ADDR`: Server bind address in HOST:PORT format (default: 0.0.0.0:3000)
- `CAS3_S3_KEY_PREFIX`: Prefix for S3 object keys (default: empty string)
  - Example: `hashstore/` will store files as `hashstore/<sha256>`
  - Include trailing slash for directory-like organization
- `AWS_REGION`: AWS region where your S3 bucket is located (standard AWS variable)
- `AWS_ACCESS_KEY_ID`: AWS access key with S3 permissions (standard AWS variable)
- `AWS_SECRET_ACCESS_KEY`: AWS secret key (standard AWS variable)

## Building and Running

### Prerequisites

- Rust 1.70 or higher
- AWS credentials with S3 access
- An S3 bucket for storage

### Build

```bash
cargo build --release
```

### Run

```bash
# Load environment variables and start the server
cargo run --release

# Or run the compiled binary
./target/release/cas3
```

The server will start on `http://localhost:3000` by default (or the address specified in `CAS3_BIND_ADDR`).

## API Endpoints

### Upload File

**Endpoint**: `PUT /upload/{jwt_token}`

**JWT Token Claims**:
- `sha256`: The SHA-256 hash of the file (required)
- `content_length`: The size of the file in bytes (required)
- `exp`: Token expiration timestamp (required)

**Response**:
- `200 OK`: Upload successful
- `400 Bad Request`: Invalid token or file validation failed
- `500 Internal Server Error`: S3 upload failed

## Creating JWT Tokens

JWT tokens must be signed with the `JWT_SECRET` using the HS256 algorithm.

### Token Structure

```json
{
  "sha256": "file_sha256_hash",
  "content_length": 12345,
  "exp": 1234567890
}
```

### Python Example

```python
import jwt
import hashlib
import time

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def create_jwt_token(sha256_hash, content_length, secret):
    """Create JWT token with SHA256 and content length claims."""
    payload = {
        'sha256': sha256_hash,
        'content_length': content_length,
        'exp': int(time.time()) + 3600  # Token expires in 1 hour
    }
    return jwt.encode(payload, secret, algorithm='HS256')

def make_jwt_from_file(file_path, secret):
    """Create JWT token directly from a file."""
    # Calculate SHA256 hash
    sha256_hash = calculate_sha256(file_path)

    # Get file size
    content_length = os.path.getsize(file_path)

    # Create and return JWT token
    return create_jwt_token(sha256_hash, content_length, secret)
```

## Client Usage

### Creating and Using JWT Tokens

```python
# Create JWT token from a file directly
token = make_jwt_from_file("myfile.pdf", os.environ["CAS3_JWT_SECRET"])
```

### Full Upload Example

```python
import requests
import os

# File details
file_path = "document.pdf"

# Create JWT token from file
token = make_jwt_from_file(file_path, os.environ["CAS3_JWT_SECRET"])

# Upload file
with open(file_path, 'rb') as f:
    response = requests.put(
        f"http://localhost:3000/upload/{token}",
        data=f,
        headers={'Content-Type': 'application/octet-stream'}
    )

if response.status_code == 200:
    print(f"Upload successful! File stored as: {sha256_hash}")
else:
    print(f"Upload failed: {response.text}")
```

## Security Considerations

1. **JWT Secret**: Keep your JWT secret secure and never commit it to version control
2. **Token Expiration**: Always set reasonable expiration times for JWT tokens
3. **HTTPS**: Use HTTPS in production to protect JWT tokens in transit
4. **File Size Limits**: Consider implementing file size limits to prevent abuse
5. **Rate Limiting**: Implement rate limiting for production deployments

## S3 Storage Structure

Files are stored in S3 with the following key format:
```
<prefix><sha256_hash>
```

The prefix is configured via `CAS3_S3_KEY_PREFIX` (defaults to empty string).

Examples:
- Without prefix: `a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3`
- With prefix `hashstore/`: `hashstore/a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3`
- With prefix `cas3/files/`: `cas3/files/a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3`


## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

[Your Contributing Guidelines Here]
