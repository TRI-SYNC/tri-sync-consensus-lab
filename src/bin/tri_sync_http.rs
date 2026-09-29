use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tiny_http::{Header, Method, Response, Server};

/// Caps concurrent `/events` streams. Each one holds its own thread open
/// for as long as the client stays connected, so with no cap a burst of
/// clients (or a handful that never disconnect) could spawn unbounded
/// threads. Generous on purpose - this serves local telemetry, not the
/// public internet - the point is a bound, not a low one.
const MAX_EVENTS_CONNECTIONS: usize = 100;

/// Decrements the shared open-connections counter when an `/events`
/// stream ends, on every exit path (normal disconnect, write error, or a
/// panic) rather than just the one at the bottom of `stream_events`.
struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

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

fn run_server(file_path: PathBuf, port: u16, max_events_connections: usize) {
    let addr = format!("0.0.0.0:{port}");
    eprintln!("SSE server reading {:?} on http://{addr}", file_path);

    let cache: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cache_bg = cache.clone();
    let file_bg = file_path.clone();
    let events_connections: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

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
        let events_connections = events_connections.clone();
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
                let prev_open = events_connections.fetch_add(1, Ordering::SeqCst);
                if prev_open >= max_events_connections {
                    events_connections.fetch_sub(1, Ordering::SeqCst);
                    let resp = Response::from_string("too many open /events connections")
                        .with_status_code(503);
                    let _ = request.respond(resp);
                    return;
                }
                let _guard = ConnectionGuard(events_connections.clone());
                let writer = request.into_writer();
                stream_events(writer, cache);
                return;
            }

            let resp = Response::from_string("not found").with_status_code(404);
            let _ = request.respond(resp);
        });
    }
}

fn main() {
    let (file_path, port) = parse_args();
    run_server(file_path, port, MAX_EVENTS_CONNECTIONS);
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};

    /// Binds to port 0 to get an OS-assigned free port, then releases it
    /// immediately - good enough for a test server started moments later,
    /// and avoids hardcoding a port that might already be in use.
    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn events_stream_new_lines_incrementally_not_as_a_batch_at_connect_time() {
        let dir = std::env::temp_dir().join(format!("tri_sync_http_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("telemetry.jsonl");
        std::fs::write(&file_path, "").unwrap();

        let port = free_port();
        let server_file = file_path.clone();
        thread::spawn(move || run_server(server_file, port, MAX_EVENTS_CONNECTIONS));
        // give the server time to bind and the cache-refresh thread time to start
        thread::sleep(Duration::from_millis(500));

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        stream.write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n").unwrap();

        // Append a uniquely marked line only *after* the connection is
        // already open. A batch-at-connect-time implementation sends its
        // one complete response immediately using whatever backlog
        // existed at connect time, then the response ends - it could
        // never see a line appended afterward. Real streaming should
        // deliver it on this same connection well within the tailer's
        // ~300ms poll interval.
        thread::sleep(Duration::from_millis(200));
        let marker = "STREAM_TEST_MARKER_12345";
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&file_path).unwrap();
            writeln!(f, "{{\"marker\":\"{marker}\"}}").unwrap();
        }

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while Instant::now() < deadline {
            match stream.read(&mut chunk) {
                Ok(0) => break, // connection closed - a batch response would do this
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if String::from_utf8_lossy(&buf).contains(marker) {
                        found = true;
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => panic!("read error: {e}"),
            }
        }
        assert!(
            found,
            "expected the line appended after connecting to arrive on the still-open /events \
             connection within 5s; got {} bytes: {}",
            buf.len(), String::from_utf8_lossy(&buf)
        );
    }

    #[test]
    fn health_stays_responsive_while_an_events_connection_is_open() {
        let dir = std::env::temp_dir().join(format!("tri_sync_http_test2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("telemetry.jsonl");
        std::fs::write(&file_path, "").unwrap();

        let port = free_port();
        let server_file = file_path.clone();
        thread::spawn(move || run_server(server_file, port, MAX_EVENTS_CONNECTIONS));
        thread::sleep(Duration::from_millis(500));

        // Open /events and leave it hanging (never read its response) -
        // if the server handled requests inline on one loop instead of a
        // thread per request, this would starve every request behind it.
        let mut events_stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        events_stream.write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();

        let mut health_stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        health_stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        health_stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();

        let mut resp = Vec::new();
        health_stream.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "expected /health to answer promptly; got: {text}");
        assert!(text.ends_with("ok") || text.contains("\r\n\r\nok"), "expected body \"ok\"; got: {text}");
    }

    #[test]
    fn events_connections_beyond_the_cap_get_503_without_disturbing_existing_streams() {
        let dir = std::env::temp_dir().join(format!("tri_sync_http_test3_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("telemetry.jsonl");
        std::fs::write(&file_path, "").unwrap();

        let port = free_port();
        let server_file = file_path.clone();
        let cap = 2usize;
        thread::spawn(move || run_server(server_file, port, cap));
        thread::sleep(Duration::from_millis(500));

        // Open `cap` connections and leave them hanging, same as the
        // responsiveness test above - each one holds a thread and a slot
        // in the counter for the rest of this test.
        let mut open_streams = Vec::new();
        for _ in 0..cap {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            open_streams.push(s);
            // give the server's spawned thread time to register the
            // connection (fetch_add) before the next one connects, so the
            // count this test relies on isn't racy.
            thread::sleep(Duration::from_millis(200));
        }

        // The (cap + 1)th connection should be turned away with 503.
        let mut over_cap = TcpStream::connect(("127.0.0.1", port)).unwrap();
        over_cap.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        over_cap.write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        over_cap.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 503"), "expected the over-cap connection to get 503; got: {text}");

        // One of the connections that was already open and under the cap
        // should still be a live, working stream, not something the
        // rejection above disturbed.
        let mut still_open = open_streams.remove(0);
        still_open.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut head = [0u8; 15];
        still_open.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 OK", "expected the already-open stream to still be serving normally");
    }
}
