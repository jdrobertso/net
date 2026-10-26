// Tests for the HTTP client against a local test server. The server runs
// on worker threads in the same program, so the tests use no internet.
// Threads need a native build:
//
//   goose build http_test.goose && http_test
//
// Run it in the test directory, because the server reads data/hello.*.
// Each response from the server has an X-Conn header with the port of the
// client. Thus a test can see if two requests used the same connection.

import net from "..";
import net.http;
import net.compress;
import net.client;
import std;
import os;

// ---------------------------------------------------------------- the server

thread_fn server(l: net::Conn) {
    loop {
        let c = net::accept(l, 0);
        if net::ok(c) {
            serve(c);
            net::close(c);
        }
    }
}

// Serves the requests on one connection until the client closes it, or
// until a route closes it.
fn serve(c: net::Conn) {
    var buf: u8[>..] = [];
    loop {
        var end = find(buf, "\r\n\r\n");
        while end < 0 {
            if net::recv(c, buf) <= 0 { return; }
            end = find(buf, "\r\n\r\n");
        }
        var body_len = 0;
        let cl, has_cl = http::find_header(buf[..end], "content-length");
        if has_cl { let v, _ = parse_int(cl); body_len = v; }
        let total = end + 4 + body_len;
        while buf.len < total { if net::recv(c, buf) <= 0 { return; } }
        var req: u8[>..] = [];
        req.append(buf[..total]);
        var rest: u8[>..] = [];
        rest.append(buf[total..]);
        buf.clear();
        buf.append(rest);
        if !respond(c, req, end + 4) { return; }
    }
}

fn send_response(c: net::Conn, status: u8[:], headers: u8[:], body: u8[:], is_head: bool) {
    var peer: u8[>..] = [];
    let port = net::peer(c, peer);
    var out: u8[>..] = [];
    format(out, "HTTP/1.1 ", status, "\r\nContent-Length: ", body.len, "\r\nX-Conn: ", port, "\r\n", headers, "\r\n");
    if !is_head { out.append(body); }
    net::send(c, out);
}

fn load(name: u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    read_file(str("data/", name), d);
    return d;
}

// Returns false when the server must close the connection.
fn respond(c: net::Conn, req: u8[:], head_len: i64) -> bool {
    let eol = find(req, "\r\n");
    let parts = split(req[..eol], ' ');
    let method = parts[0];
    var target = parts[1];
    // A request through a proxy gives the full URL. Use only its path.
    if starts_with(target, "http://") {
        let slash = find(target[7..], "/");
        target = if slash >= 0 { target[7 + slash..] } else { "/" };
    }
    let q = find(target, "?");
    let path = if q >= 0 { target[..q] } else { target };
    let is_head = method == "HEAD";

    if method == "CONNECT" {
        net::send(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
        return false;
    }
    if path == "/hello" { send_response(c, "200 OK", "", "hello", is_head); return true; }
    if path == "/echo" { send_response(c, "200 OK", "", req, is_head); return true; }
    if path == "/chunked" {
        net::send(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        net::send(c, "5;ext=1\r\nhello\r\n");
        net::send(c, "6\r\n world\r\n0\r\nX-Trailer: yes\r\n\r\n");
        return true;
    }
    if path == "/gzip" { send_response(c, "200 OK", "Content-Encoding: gzip\r\n", load("hello.gz"), is_head); return true; }
    if path == "/deflate-raw" { send_response(c, "200 OK", "Content-Encoding: deflate\r\n", load("hello.raw"), is_head); return true; }
    if path == "/deflate-zlib" { send_response(c, "200 OK", "Content-Encoding: deflate\r\n", load("hello.zz"), is_head); return true; }
    if path == "/close" {
        net::send(c, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil the end");
        return false;
    }
    if path == "/http10" {
        net::send(c, "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nold");
        return false;
    }
    if path == "/continue" {
        net::send(c, "HTTP/1.1 100 Continue\r\n\r\n");
        send_response(c, "200 OK", "", "after continue", is_head);
        return true;
    }
    if path == "/redirect" { send_response(c, "302 Found", "Location: hello\r\n", "", is_head); return true; }
    if path == "/see-other" { send_response(c, "303 See Other", "Location: /echo\r\n", "", is_head); return true; }
    if path == "/loop" { send_response(c, "302 Found", "Location: /loop\r\n", "", is_head); return true; }
    if path == "/setcookie-a" { sleep_ms(300); send_response(c, "200 OK", "Set-Cookie: a=1; Path=/\r\n", "a", is_head); return true; }
    if path == "/setcookie-b" { sleep_ms(300); send_response(c, "200 OK", "Set-Cookie: b=2; Path=/\r\n", "b", is_head); return true; }
    if path == "/setcookie" {
        send_response(c, "200 OK", "Set-Cookie: k=v; Path=/\r\nSet-Cookie: other=2; Path=/\r\n", "set", is_head);
        return true;
    }
    // The response does not say "Connection: close", but the server closes
    // the connection after it. The client must retry the next request.
    if path == "/drop" { send_response(c, "200 OK", "", "dropped", is_head); return false; }
    if path == "/slow" { sleep_ms(2000); send_response(c, "200 OK", "", "late", is_head); return true; }
    if path == "/big" {
        var b: u8[>..] = [];
        for i in 300000 { b.push((i % 251) as! u8); }
        send_response(c, "200 OK", "", b, is_head);
        return true;
    }
    if path == "/bigchunked" {
        net::send(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        var b: u8[>..] = [];
        for k in 300 {
            b.clear();
            b.append("3e8\r\n");                                   // 1000 bytes
            for i in 1000 { b.push(((k * 1000 + i) % 251) as! u8); }
            b.append("\r\n");
            net::send(c, b);
        }
        net::send(c, "0\r\n\r\n");
        return true;
    }
    send_response(c, "404 Not Found", "", "no such page", is_head);
    return true;
}

// ---------------------------------------------------------------- a tunnel proxy

// Copies bytes from one connection to the other until one side closes.
// Then it closes the two connections.
thread_fn pump(from: net::Conn, to: net::Conn) {
    var b: u8[>..] = [];
    loop {
        b.clear();
        if net::recv(from, b) <= 0 { break; }
        if !net::send(to, b) { break; }
    }
    net::close(from);
    net::close(to);
}

// A proxy that accepts only CONNECT. It connects to the target and starts
// two pump threads, one for each direction.
thread_fn tunnel_proxy(l: net::Conn) {
    loop {
        let c = net::accept(l, 0);
        guard net::ok(c) else { continue; }
        var head: u8[>..] = [];
        while find(head, "\r\n\r\n") < 0 { if net::recv(c, head) <= 0 { break; } }
        let parts = split(head[..max(find(head, "\r\n"), 0)], ' ');
        let colon = if parts.len >= 2 { rfind(parts[1], ":") } else { -1 };
        if parts.len < 2 || parts[0] != "CONNECT" || colon < 0 {
            net::send(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            net::close(c);
            continue;
        }
        let port, _ = parse_int(parts[1][colon + 1..]);
        let up = net::connect(parts[1][..colon], port, false, 10000);
        if !net::ok(up) {
            net::send(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            net::close(c);
            continue;
        }
        net::send(c, "HTTP/1.1 200 Connection Established\r\n\r\n");
        thread_spawn(pump, c, up);
        thread_spawn(pump, up, c);
    }
}

// ---------------------------------------------------------------- the tests

var failures = 0;

fn fail(what: u8[:]) {
    print("FAIL ", what);
    failures++;
}

fn expect(what: u8[:], r: const http::Response&, status: i64, body: u8[:]) {
    if r.status != status || http::body(r) != body {
        fail(str(what, ": status ", r.status, ", body \"", http::body(r)[..min(http::body(r).len, 200)], "\""));
    }
}

fn conn_of(r: const http::Response&) -> const u8[:] {
    let v, _ = http::header(r, "x-conn");
    return v;
}

fn contains(s: u8[:], part: u8[:]) -> bool { find(s, part) >= 0 }

fn main() {
    let l = net::listen("127.0.0.1", 0);
    guard net::ok(l) else { print("cannot listen: ", net::error()); exit(1); }
    let port = net::local_port(l);
    for i in 16 { thread_spawn(server, l); }
    let base = str("http://127.0.0.1:", port);
    let opts = http::Options { use_env_proxy: false, .. };
    var s = http::session(opts);

    // ---- basic requests and keep-alive
    let a = http::get(s, str(base, "/hello"));
    expect("hello", a, 200, "hello");
    let b = http::get(s, str(base, "/hello"));
    let b2 = http::get(s, str(base, "/hello"));
    if conn_of(a) != conn_of(b) || conn_of(b) != conn_of(b2) { fail("keep-alive: the requests used different connections"); }
    let h = http::request(s, "HEAD", str(base, "/hello"));
    if h.status != 200 || http::body(h).len != 0 || conn_of(h) != conn_of(a) { fail("HEAD on a kept connection"); }

    // ---- framing
    { let t = http::get(s, str(base, "/chunked")); expect("chunked", t, 200, "hello world"); }
    let cont = http::get(s, str(base, "/continue"));
    expect("100 Continue", cont, 200, "after continue");
    let closed = http::get(s, str(base, "/close"));
    expect("close-delimited", closed, 200, "until the end");
    { let t = http::get(s, str(base, "/http10")); expect("HTTP/1.0", t, 200, "old"); }
    let after = http::get(s, str(base, "/hello"));
    if conn_of(after) == conn_of(a) { fail("a connection after Connection: close came from the pool"); }

    // ---- compression
    let hello = "hello, hello, hello goose\n";
    { let t = http::get(s, str(base, "/gzip")); expect("gzip", t, 200, hello); }
    { let t = http::get(s, str(base, "/deflate-raw")); expect("deflate (raw)", t, 200, hello); }
    { let t = http::get(s, str(base, "/deflate-zlib")); expect("deflate (zlib)", t, 200, hello); }
    let raw_opts = http::Options { decompress: false, use_env_proxy: false, .. };
    let undecoded = http::get(str(base, "/gzip"), raw_opts);
    if http::body(undecoded) != load("hello.gz") { fail("decompress: false must keep the gzip bytes"); }

    // ---- the request that the client sends
    let e = http::request(s, "POST", str(base, "/echo"), "X-Test: 1\r\nUser-Agent: tester", "a=1&b=2");
    let sent = http::body(e);
    if !starts_with(sent, "POST /echo HTTP/1.1\r\n") { fail(str("request line: ", sent)); }
    if !contains(sent, str("Host: 127.0.0.1:", port, "\r\n")) { fail("Host header"); }
    if !contains(sent, "User-Agent: tester\r\n") || contains(sent, "goose-net") { fail("User-Agent override"); }
    if !contains(sent, "Accept-Encoding: gzip, deflate\r\n") { fail("Accept-Encoding"); }
    if !contains(sent, "Content-Length: 7\r\n") || !ends_with(sent, "\r\n\r\na=1&b=2") { fail("POST body"); }
    let unsafe_target = http::get(s, str(base, "/echo?q=a b"));
    if !starts_with(http::body(unsafe_target), "GET /echo?q=a%20b HTTP/1.1") { fail("a space in the target"); }

    // ---- redirects
    let r = http::get(s, str(base, "/redirect"));
    expect("relative redirect", r, 200, "hello");
    if r.redirects != 1 || !ends_with(http::final_url(r), "/hello") { fail("redirect count or final URL"); }
    let so = http::request(s, "POST", str(base, "/see-other"), "", "data");
    if !starts_with(http::body(so), "GET /echo") || contains(http::body(so), "data") { fail("303 must become a GET without a body"); }
    let lp = http::get(s, str(base, "/loop"));
    if http::ok(lp) || !contains(http::error(lp), "more than 10 redirects") { fail(str("redirect loop: ", http::error(lp))); }

    // ---- cookies
    http::get(s, str(base, "/setcookie"));
    let ce = http::get(s, str(base, "/echo"));
    if !contains(http::body(ce), "Cookie: k=v; other=2\r\n") { fail(str("cookies were not sent: ", http::body(ce))); }

    // ---- a stale pooled connection
    let d = http::get(s, str(base, "/drop"));
    expect("drop", d, 200, "dropped");
    let again = http::get(s, str(base, "/hello"));
    expect("retry after a dropped connection", again, 200, "hello");
    if conn_of(again) == conn_of(d) { fail("the retry used the dropped connection"); }

    // ---- streaming
    for k in 2 {
        let route = if k == 0 { "/big" } else { "/bigchunked" };
        var got = 0;
        var crc: u32 = 0;
        var parts = 0;
        let st = http::stream(s, "GET", str(base, route)) { chunk, total =>
            got += chunk.len;
            parts++;
            crc = compress::crc32(chunk, crc);
        };
        var want: u8[>..] = [];
        for i in 300000 { want.push((i % 251) as! u8); }
        if st.status != 200 || got != 300000 || crc != compress::crc32(want) || http::body(st).len != 0 {
            fail(str("stream ", route, ": ", got, " bytes in ", parts, " parts, ", http::error(st)));
        }
    }
    let after_stream = http::get(s, str(base, "/hello"));
    expect("a request after a stream", after_stream, 200, "hello");

    // ---- limits and timeouts
    let small = http::get(str(base, "/big"), http::Options { max_bytes: 1000, use_env_proxy: false, .. });
    if http::ok(small) || !contains(http::error(small), "larger than max_bytes") { fail("max_bytes"); }
    let slow = http::get(str(base, "/slow"), http::Options { timeout_ms: 300, use_env_proxy: false, .. });
    if http::ok(slow) || !contains(http::error(slow), "time limit") { fail(str("timeout: ", http::error(slow))); }

    // ---- proxies: the test server is also the proxy
    let proxy = str("http://user:pa%20ss@127.0.0.1:", port);
    let popts = http::Options { proxy: proxy, use_env_proxy: false, .. };
    let pr = http::get("http://example.invalid/echo", popts);
    let ptext = http::body(pr);
    if !starts_with(ptext, "GET http://example.invalid/echo HTTP/1.1\r\n") { fail(str("proxy request line: ", ptext)); }
    if !contains(ptext, "Host: example.invalid\r\n") { fail("proxy Host header"); }
    if !contains(ptext, "Proxy-Authorization: Basic dXNlcjpwYSBzcw==\r\n") { fail("proxy authorization"); }
    let tun = http::get("https://example.invalid/", popts);
    if http::ok(tun) || !contains(http::error(tun), "407 Proxy Authentication Required") {
        fail(str("CONNECT refusal: ", http::error(tun)));
    }
    let direct = http::get(str(base, "/echo"), http::Options { proxy: proxy, use_env_proxy: false, no_proxy: "localhost, 127.0.0.1", .. });
    if !starts_with(http::body(direct), "GET /echo HTTP/1.1") { fail("no_proxy"); }

    // ---- a real CONNECT tunnel and TLS through it (only with --online)
    let a_args = args();
    if a_args.len > 1 && a_args[1] == "--online" {
        let tl = net::listen("127.0.0.1", 0);
        thread_spawn(tunnel_proxy, tl);
        let tproxy = str("http://127.0.0.1:", net::local_port(tl));
        let topts = http::Options { proxy: tproxy, use_env_proxy: false, .. };
        var ts = http::session(topts);
        let t1 = http::get(ts, "https://example.com/");
        let t2 = http::get(ts, "https://example.com/");
        if !http::ok(t1) || t1.status != 200 || find(http::body(t1), "Example Domain") < 0 {
            fail(str("tunnel: ", t1.status, " ", http::error(t1)));
        }
        if !http::ok(t2) || ts.pool.len != 1 { fail(str("tunnel keep-alive: ", http::error(t2))); }
        http::close(ts);
        print("online: the CONNECT tunnel test ran");
    }

    // ---- the client that does not block
    {
        var cl = http::client(opts, 4);

        // Four requests of 2 s each, on four workers: about 2 s in total, and
        // the main thread continues while they run.
        let t0 = clock();
        for i in 4 { http::submit(cl, "GET", str(base, "/slow")); }
        var loops = 0;
        var done = 0;
        while done < 4 {
            let id, r = http::poll(cl);
            if id < 0 { loops++; sleep_ms(5); continue; }
            if r.status != 200 || http::body(r) != "late" { fail(str("client: job ", id, " gave ", r.status)); }
            done++;
        }
        let secs = clock() - t0;
        if secs > 3.5 { fail(str("client: four parallel requests took ", secs, " s")); }
        if loops < 10 { fail("client: the main thread did not run while it waited"); }

        // next with a time limit.
        http::submit(cl, "GET", str(base, "/slow"));
        let tid, _ = http::next(cl, 50);
        if tid != -1 { fail("client: next must give -1 when the time limit expires"); }
        let sid, sr = http::next(cl);
        if sid < 0 || sr.status != 200 { fail("client: next without a time limit"); }
        let nid, _ = http::next(cl);
        if nid != -1 { fail("client: next with nothing in flight must give -1 at once"); }

        // Two requests that set cookies at the same time: the jar keeps both.
        let ia = http::submit(cl, "GET", str(base, "/setcookie-a"));
        let ib = http::submit(cl, "GET", str(base, "/setcookie-b"));
        http::next(cl);
        http::next(cl);
        let eid = http::submit(cl, "GET", str(base, "/echo"));
        let _, er = http::next(cl);
        if !contains(http::body(er), "Cookie: a=1; b=2\r\n") && !contains(http::body(er), "Cookie: b=2; a=1\r\n") {
            fail(str("client: cookie merge: ", http::body(er)));
        }

        // Progress messages for a large body.
        let pid = http::submit(cl, "GET", str(base, "/big"), "", "", true);
        var last = 0;
        var msgs = 0;
        var big_len = 0;
        loop {
            let p, gotp = http::progress(cl);
            if gotp {
                if p.id != pid || p.got < last || p.total != 300000 { fail(str("client: progress ", p)); }
                last = p.got;
                msgs++;
                continue;
            }
            let id, r = http::poll(cl);
            if id == pid { big_len = http::body(r).len; break; }
            sleep_ms(1);
        }
        // The worker sends the last Progress before Done, so the queue has all of them now.
        loop { let p, gotp = http::progress(cl); guard gotp else { break; } last = p.got; msgs++; }
        if big_len != 300000 || last != 300000 || msgs < 2 { fail(str("client: progress gave ", msgs, " messages, last ", last, ", body ", big_len)); }

        // A failure comes back as a Response with status 0.
        http::submit(cl, "GET", "http://127.0.0.1:1/");
        let _, xr = http::next(cl);
        if http::ok(xr) || !contains(http::error(xr), "cannot connect") { fail(str("client: error ", http::error(xr))); }

        http::close(cl);
    }

    // ---- data: URLs
    { let t = http::get(s, "data:,hi%20there"); expect("data: URL", t, 200, "hi there"); }

    http::close(s);
    if failures == 0 { print("http: all passed"); } else { print("http: ", failures, " failed"); exit(1); }
    exit(0);
}
