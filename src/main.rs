use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};
use digest::Digest;
use hex;
use reqwest::blocking::Client;
use sha2::Sha256;
use tempfile::NamedTempFile;
use url::Url;

/// Simple CAS (Content Addressable Storage) CLI
#[derive(Parser)]
#[command(name = "cas3", about = "Content Addressable Storage")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Save a file from a URL (http/https/file)
    Save {
        /// URL of the file to fetch
        url: String,
    },
    /// Fetch a file by its SHA256 hash
    Fetch {
        /// SHA256 hash of the file
        sha: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let storage_dir = "storage";

    // Ensure storage directory exists
    if let Err(e) = fs::create_dir_all(storage_dir) {
        eprintln!("Failed to create storage directory: {}", e);
        process::exit(1);
    }

    match &cli.command {
        Commands::Save { url } => {
            if let Err(e) = handle_save(url, storage_dir) {
                eprintln!("Error saving {}: {}", url, e);
                process::exit(1);
            }
        }
        Commands::Fetch { sha } => {
            if let Err(e) = handle_fetch(sha, storage_dir) {
                eprintln!("Error fetching {}: {}", sha, e);
                process::exit(1);
            }
        }
    }
}

/// Handle the `save` command
fn handle_save(url_str: &str, storage_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_url = Url::parse(url_str)?;
    match parsed_url.scheme() {
        "http" | "https" => {
            // Download the file
            println!("Downloading from {} ...", url_str);
            let client = Client::new();
            let mut resp = client.get(url_str).send()?;
            if !resp.status().is_success() {
                return Err(format!("HTTP error: {}", resp.status()).into());
            }

            // Write to a temporary file while computing SHA
            let mut temp = NamedTempFile::new()?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            loop {
                let n = resp.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                temp.write_all(&buffer[..n])?;
                hasher.update(&buffer[..n]);
            }
            let sha = hex::encode(hasher.finalize());
            let dest_path = Path::new(storage_dir).join(&sha);

            if dest_path.exists() {
                // Already stored, discard temp
                println!("File already exists with SHA {}", sha);
                temp.close()?; // delete temp
            } else {
                // Move temp to storage
                temp.persist(&dest_path)?;
                println!("Saved as {}", dest_path.display());
            }
        }
        "file" => {
            // Copy local file
            let path = parsed_url
                .to_file_path()
                .map_err(|_| "Failed to parse file URL to path".to_string())?;
            if !path.exists() {
                return Err(format!("File {} does not exist", path.display()).into());
            }

            // Compute SHA while copying
            let mut file = fs::File::open(&path)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            let mut temp = NamedTempFile::new()?;
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                temp.write_all(&buffer[..n])?;
                hasher.update(&buffer[..n]);
            }
            let sha = hex::encode(hasher.finalize());
            let dest_path = Path::new(storage_dir).join(&sha);

            if dest_path.exists() {
                println!("File already exists with SHA {}", sha);
                temp.close()?;
            } else {
                temp.persist(&dest_path)?;
                println!("Saved as {}", dest_path.display());
            }
        }
        _ => {
            return Err(format!("Unsupported scheme: {}", parsed_url.scheme()).into());
        }
    }
    Ok(())
}

/// Handle the `fetch` command
fn handle_fetch(sha: &str, storage_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = Path::new(storage_dir).join(sha);
    if !file_path.exists() {
        return Err(format!("No file found with SHA {}", sha).into());
    }
    let abs_path = fs::canonicalize(&file_path)?;
    println!("file://{}", abs_path.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_file_save() {
        let storage_dir = tempdir().unwrap();
        let storage_path = storage_dir.path().to_str().unwrap();

        let file_dir = tempdir().unwrap();
        let file_path = file_dir.path().join("test.txt");
        fs::write(&file_path, b"hello world").unwrap();

        let url = format!("file://{}", file_path.to_str().unwrap());
        handle_save(&url, storage_path).unwrap();

        // Compute expected SHA
        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let expected_sha = hex::encode(hasher.finalize());

        let stored_path = storage_dir.path().join(&expected_sha);
        assert!(stored_path.exists());
        let content = fs::read(stored_path).unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn test_http_save() {
        let storage_dir = tempdir().unwrap();
        let storage_path = storage_dir.path().to_str().unwrap();

        let server = MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(GET).path("/file");
            then.status(200).body(b"http content");
        });

        let url = format!("http://{}{}", server.address(), "/file");
        handle_save(&url, storage_path).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"http content");
        let expected_sha = hex::encode(hasher.finalize());

        let stored_path = storage_dir.path().join(&expected_sha);
        assert!(stored_path.exists());
        let content = fs::read(stored_path).unwrap();
        assert_eq!(content, b"http content");
    }

    #[test]
    fn test_fetch() {
        let storage_dir = tempdir().unwrap();
        let storage_path = storage_dir.path().to_str().unwrap();

        // Create a file with known content and SHA
        let content = b"test content";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha = hex::encode(hasher.finalize());

        let file_path = storage_dir.path().join(&sha);
        fs::write(&file_path, content).unwrap();

        // Test fetch
        let result = handle_fetch(&sha, storage_path);
        assert!(result.is_ok());
    }
}
