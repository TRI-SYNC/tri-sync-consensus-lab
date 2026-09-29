use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tiny_http::{Server, Response, Method, Header};

fn parse_args() -> (PathBuf, u16) {
    let mut file = PathBuf::from("../telemetry/telemetry.jsonl");
    let mut port: u16 = 8787;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => { i += 1; if let Some(p) = args.get(i) { file = PathBuf::from(p); } }
            "--port" => { i += 1; if let Some(p) = args.get(i) { port = p.parse().unwrap_or(port); } }
            _ => {}
        }
        i += 1;
    }
    (file, port)
}

fn main() {
    let (file_path, port) = parse_args();
    let addr = format!("0.0.0.0:{port}");
    eprintln!("SSE server reading {:?} on http://{addr}", file_path);

    let cache: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cache_bg = cache.clone();
    let file_bg = file_path.clone();

    // refresh file cache
    thread::spawn(move || {
        loop {
            if let Ok(text) = fs::read_to_string(&file_bg) {
                let lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                let mut guard = cache_bg.lock().unwrap();
                *guard = lines;
            }
            thread::sleep(Duration::from_millis(300));
        }
    });

    let server = Server::http(&addr).expect("failed to bind");

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().clone();

        if method != Method::Get {
            let resp = Response::from_string("method not allowed").with_status_code(405);
            let _ = request.respond(resp);
            continue;
        }

        if url.starts_with("/health") {
            let resp = Response::from_string("ok").with_status_code(200);
            let _ = request.respond(resp);
            continue;
        }

        if url.starts_with("/latest") {
            let guard = cache.lock().unwrap();
            let body = guard.last().cloned().unwrap_or_else(|| "".to_string());
            let mut resp = Response::from_string(body).with_status_code(200);
            resp.add_header(Header::from_bytes("Content-Type", "application/json").unwrap());
            resp.add_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
            let _ = request.respond(resp);
            continue;
        }

        if url.starts_with("/events") {
            // NOTE: tiny_http doesn't support true streaming responses. This returns a batch
            // in SSE format (interface compatible with upgrading to axum/hyper later).
            let guard = cache.lock().unwrap();
            let tail = 250usize;
            let start = guard.len().saturating_sub(tail);
            let mut body = String::new();
            for line in &guard[start..] {
                body.push_str("event: telemetry\n");
                body.push_str("data: ");
                body.push_str(line);
                body.push_str("\n\n");
            }
            let mut resp = Response::from_string(body).with_status_code(200);
            resp.add_header(Header::from_bytes("Content-Type", "text/event-stream").unwrap());
            resp.add_header(Header::from_bytes("Cache-Control", "no-cache").unwrap());
            resp.add_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
            let _ = request.respond(resp);
            continue;
        }

        let resp = Response::from_string("not found").with_status_code(404);
        let _ = request.respond(resp);
    }
}
