#!/usr/bin/env python3
"""
Test script to verify SHA256 validation by sending a file with a fake SHA256.
This should fail because S3 will verify the actual content doesn't match the claimed SHA256.
"""

import sys
import hashlib
import jwt
import requests
import time
from pathlib import Path

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

def test_fake_sha256(file_path, server_url, jwt_secret):
    """Test upload with fake SHA256 to verify S3 validation."""
    print(f"🔍 Testing fake SHA256 with file: {file_path}")

    # Calculate real SHA256 and file size
    real_sha256 = calculate_sha256(file_path)
    content_length = Path(file_path).stat().st_size

    print(f"Real SHA256: {real_sha256}")
    print(f"Content Length: {content_length} bytes")

    # Create a fake SHA256 (just change some characters)
    fake_sha256 = "1234567890abcdef" + real_sha256[16:]  # Replace first 16 chars
    print(f"Fake SHA256: {fake_sha256}")

    # Generate JWT token with FAKE SHA256
    token = create_jwt_token(fake_sha256, content_length, jwt_secret)
    print(f"JWT Token: {token}")

    # Upload with fake SHA256
    upload_url = f"{server_url}/upload/{token}"
    print(f"Uploading to: {upload_url}")

    with open(file_path, 'rb') as f:
        response = requests.put(
            upload_url,
            data=f,
            headers={'Content-Type': 'application/octet-stream'}
        )

    print(f"\nResponse Status: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"Response Body: {response.text}")

    if response.status_code == 200:
        print("❌ UNEXPECTED: Upload should have failed with fake SHA256!")
        return False
    else:
        print("✅ EXPECTED: Upload failed with fake SHA256 (S3 validation working)")
        if "checksum" in response.text.lower() or "invalid" in response.text.lower():
            print("✅ Error message indicates checksum/validation failure")
        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_fake_sha.py <file_path> [server_url] [jwt_secret]")
        print("Example: python test_fake_sha.py test.txt http://localhost:3000 your_jwt_secret_here")
        sys.exit(1)

    file_path = sys.argv[1]
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:3000"
    jwt_secret = sys.argv[3] if len(sys.argv) > 3 else "your_jwt_secret_here"

    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        sys.exit(1)

    print("🧪 CAS3 Fake SHA256 Test")
    print("=" * 50)

    try:
        success = test_fake_sha256(file_path, server_url, jwt_secret)
        if success:
            print("\n🎉 Test PASSED: SHA256 verification is working correctly!")
        else:
            print("\n💥 Test FAILED: SHA256 verification is NOT working!")
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
