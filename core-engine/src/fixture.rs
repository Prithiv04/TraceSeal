use std::{io::BufReader, sync::Arc};

use rustls::ServerConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const CERT: &[u8] = include_bytes!("../tests/fixtures/server-cert.pem");
const KEY: &[u8] = include_bytes!("../tests/fixtures/server-key.pem");
const UNTRUSTED_CERT: &[u8] = include_bytes!("../tests/fixtures/untrusted-server-cert.pem");
const UNTRUSTED_KEY: &[u8] = include_bytes!("../tests/fixtures/untrusted-server-key.pem");

pub async fn serve_fixture(
    addr: &str,
    untrusted_cert: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_pem, key_pem) = if untrusted_cert {
        (UNTRUSTED_CERT, UNTRUSTED_KEY)
    } else {
        (CERT, KEY)
    };
    let certs =
        rustls_pemfile::certs(&mut BufReader::new(cert_pem)).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem))?
        .ok_or("fixture server key is missing")?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    eprintln!("TRACESEAL local HTTPS fixture listening at https://{addr}");
    loop {
        let (socket, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(socket).await else {
                return;
            };
            let mut request = vec![0u8; 8192];
            let Ok(n) = stream.read(&mut request).await else {
                return;
            };
            let request = String::from_utf8_lossy(&request[..n]);
            let path = request
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default();
            let (status, body) = match path {
                "/trace-seal-503" => (
                    "503 Service Unavailable",
                    r#"{"status":503,"error":"Service Unavailable","service":"TRACESEAL Demo API","message":"The service is temporarily unavailable."}"#,
                ),
                "/trace-seal-200" => (
                    "200 OK",
                    r#"{"status":200,"service":"TRACESEAL Demo API","message":"Fixture is healthy."}"#,
                ),
                "/trace-seal-404" => (
                    "404 Not Found",
                    r#"{"error":"Not Found","service":"TRACESEAL Demo API"}"#,
                ),
                "/trace-seal-delay" => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    (
                        "200 OK",
                        r#"{"status":200,"message":"Delayed fixture response."}"#,
                    )
                }
                _ => ("404 Not Found", r#"{"error":"Not Found"}"#),
            };
            let response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}
