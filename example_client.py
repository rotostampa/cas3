#!/usr/bin/env python3
"""
Example client for CAS3 proxy server.
Generates JWT tokens and uploads files to the CAS3 server.

Requirements:
pip install PyJWT requests

Usage:
python example_client.py <file_path> [server_url] [jwt_secret]

By default, jwt_secret will use the CAS3_JWT_SECRET environment variable if not provided.
"""

import sys
import hashlib
import jwt
import requests
import time
from pathlib import Path
import os

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

def upload_file(file_path, server_url, jwt_secret):
    """Upload file to CAS3 proxy server."""
    print(f"Processing file: {file_path}")

    # Calculate SHA256 and file size
    sha256_hash = calculate_sha256(file_path)
    content_length = Path(file_path).stat().st_size

    print(f"SHA256: {sha256_hash}")
    print(f"Content Length: {content_length} bytes")

    # Generate JWT token
    token = create_jwt_token(sha256_hash, content_length, jwt_secret)
    print(f"JWT Token: {token}")

    # Upload to proxy server
    upload_url = f"{server_url}/upload/{token}"
    print(f"Uploading to: {upload_url}")

    with open(file_path, 'rb') as f:
        response = requests.put(
            upload_url,
            data=f,
            headers={'Content-Type': 'application/octet-stream'}
        )

    print(f"Response Status: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"Response Body: {response.text}")

    if response.status_code == 200:
        print("✅ Upload successful!")
        if response.headers.get('etag'):
            print(f"S3 ETag: {response.headers['etag']}")
        if response.headers.get('x-amz-version-id'):
            print(f"S3 Version ID: {response.headers['x-amz-version-id']}")
    else:
        print(f"❌ Upload failed!")
        print(f"Full error response: {response.text}")
        print(f"Response headers: {dict(response.headers)}")

    return response.status_code == 200

def main():
    if len(sys.argv) < 2:
        print("Usage: python example_client.py <file_path> [server_url] [jwt_secret]")
        print("Example: python example_client.py test.txt http://localhost:3000 mysecret")
        print("Note: jwt_secret defaults to CAS3_JWT_SECRET environment variable if not provided")
        sys.exit(1)

    file_path = sys.argv[1]
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:3000"
    jwt_secret = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("CAS3_JWT_SECRET", "test_secret")

    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        sys.exit(1)

    print("🚀 CAS3 Upload Client")
    print("=" * 40)

    try:
        success = upload_file(file_path, server_url, jwt_secret)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
