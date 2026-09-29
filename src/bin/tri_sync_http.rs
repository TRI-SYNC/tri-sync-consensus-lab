use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tiny_http::{Header, Method, Response, Server};

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

/// Writes one HTTP chunk (`Transfer-Encoding: chunked` framing) and flushes
/// immediately. tiny_http's own `Response`/`raw_print` path buffers written
/// data (an internal 8KB `chunked_transfer::Encoder` buffer, on top of a 1KB
/// `BufWriter` around the socket, both flushed only when the response ends)
/// with no way for a caller to force a flush mid-response - fine for a
/// batch reply, fatal for a live stream, since a slow trickle of small SSE
/// events would just sit in memory and never reach the client. Writing raw
/// chunks directly to `Request::into_writer()`'s socket handle and flushing
/// after each one is what actually gets bytes out in real time.
fn write_chunk<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    write!(w, "{:x}\r\n", data.len())?;
    w.write_all(data)?;
    w.write_all(b"\r\n")?;
    w.flush()
}

fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
    )
}

/// Streams `/events` for the lifetime of the connection: an initial backlog
/// burst (same 250-line tail the old batch response sent), then newly
/// appended telemetry lines pushed as they land in `cache`, plus a periodic
/// SSE comment so idle connections aren't reaped by proxies/browsers.
fn stream_events(mut w: Box<dyn Write + Send>, cache: Arc<Mutex<Vec<String>>>) {
    let head = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: keep-alive\r\n",
        "Access-Control-Allow-Origin: *\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
    );
    if w.write_all(head.as_bytes()).and_then(|_| w.flush()).is_err() {
        return;
    }

    let mut next_index = {
        let guard = cache.lock().unwrap();
        guard.len().saturating_sub(250)
    };
    let mut last_activity = Instant::now();

    loop {
        let new_lines: Vec<String> = {
            let guard = cache.lock().unwrap();
            if next_index < guard.len() {
                let lines = guard[next_index..].to_vec();
                next_index = guard.len();
                lines
            } else {
                Vec::new()
            }
        };

        if new_lines.is_empty() {
            thread::sleep(Duration::from_millis(300));
            if last_activity.elapsed() >= Duration::from_secs(15) {
                last_activity = Instant::now();
                if let Err(e) = write_chunk(&mut w, b": keep-alive\n\n") {
                    if !is_disconnect(&e) { eprintln!("/events write error: {e}"); }
                    return;
                }
            }
            continue;
        }

        last_activity = Instant::now();
        for line in &new_lines {
            let mut body = String::with_capacity(line.len() + 32);
            body.push_str("event: telemetry\ndata: ");
            body.push_str(line);
            body.push_str("\n\n");
            if let Err(e) = write_chunk(&mut w, body.as_bytes()) {
                if !is_disconnect(&e) { eprintln!("/events write error: {e}"); }
                return;
            }
        }
    }
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

    // One thread per request: `/events` is a long-lived streaming
    // connection, so handling it inline on this loop would stall every
    // other request (`/health`, `/latest`) behind it until the client
    // disconnected.
    for request in server.incoming_requests() {
        let cache = cache.clone();
        thread::spawn(move || {
            let url = request.url().to_string();
            let method = request.method().clone();

            if method != Method::Get {
                let resp = Response::from_string("method not allowed").with_status_code(405);
                let _ = request.respond(resp);
                return;
            }

            if url.starts_with("/health") {
                let resp = Response::from_string("ok").with_status_code(200);
                let _ = request.respond(resp);
                return;
            }

            if url.starts_with("/latest") {
                let guard = cache.lock().unwrap();
                let body = guard.last().cloned().unwrap_or_else(|| "".to_string());
                drop(guard);
                let mut resp = Response::from_string(body).with_status_code(200);
                resp.add_header(Header::from_bytes("Content-Type", "application/json").unwrap());
                resp.add_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
                let _ = request.respond(resp);
                return;
            }

            if url.starts_with("/events") {
                let writer = request.into_writer();
                stream_events(writer, cache);
                return;
            }

            let resp = Response::from_string("not found").with_status_code(404);
            let _ = request.respond(resp);
        });
    }
}
