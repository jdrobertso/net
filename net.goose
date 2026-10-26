// net: a byte stream to a host, plain or with TLS. The connection is in C
// (src/net.c). Goose holds a Conn, which is a 64-bit id. The C never uses
// an id again. Thus a closed or stale Conn fails safely. It cannot reach a
// different socket.
//
//   import net from "path/to/net";   // in the root file of the program
//   import net.url;                  // URL parsing and resolution
//   import net.http;                 // an HTTP/1.1 client on top of net
//
// Errors: a call that fails returns a zero Conn, false, or -1. Then error()
// gives the reason. Each thread has its own error message. Thus each worker
// can hold its own connections. Use a Conn from only one thread at a time.

namespace net;

import std;

// A zero id is not a connection.
struct Conn { id: u64 }

fn ok(c: Conn) -> bool { c.id != 0 }

// Finds the addresses of `host` and connects to the first address that
// answers within `timeout_ms`. With `tls`, it also does the TLS handshake.
// The handshake checks the certificate and the host name against the
// system trust store. The time limit also applies to each send and recv
// after the connect. Zero means no time limit.
extern "net_connect" fn connect(host: const u8[:], port: i64, tls: bool = false,
                                timeout_ms: i64 = 15000) -> Conn;

// Sends all of `data`, or fails.
extern "net_send" fn send(c: Conn, data: const u8[:]) -> bool;

// Appends the received bytes to `out`. It appends at least one byte and a
// maximum of `max` bytes. The limit for one call is 16 KB. If no bytes are
// ready, it waits. It returns 0 at the end of the stream. It returns -1 for
// an error or when the time limit expires.
extern "net_recv" fn recv(c: Conn, out: u8[>..]&, max: i64 = 16384) -> i64;

// Replaces the send and recv time limit that connect set.
extern "net_set_timeout" fn set_timeout(c: Conn, ms: i64) -> bool;

// Ends the TLS session, if there is one, and closes the socket. If the
// Conn is already closed, or zero, this call does nothing.
extern "net_close" fn close(c: Conn);

// Starts TLS on a connection that is already open, for example a tunnel
// through an HTTP proxy. `host` is the name that the certificate must match.
extern "net_start_tls" fn start_tls(c: Conn, host: const u8[:]) -> bool;

// ---------------------------------------------------------------- servers

// Opens a listener: a Conn that waits for connections on `host`:`port`.
// An empty host means all local addresses. Port 0 lets the system select
// a free port. Use local_port to get it. A listener has no TLS.
extern "net_listen" fn listen(host: const u8[:], port: i64, backlog: i64 = 0) -> Conn;

// Waits for the next connection on a listener, for a maximum of
// `timeout_ms`. Zero means no time limit. Returns a zero Conn when the
// time limit expires. The new Conn gets the send and recv time limit of
// the listener. Use set_timeout on the listener to change that limit.
extern "net_accept" fn accept(listener: Conn, timeout_ms: i64 = 0) -> Conn;

// Returns the local port of a connection or a listener, or -1.
extern "net_local_port" fn local_port(c: Conn) -> i64;

// Appends the address of the peer to `out`, and returns its port, or -1.
extern "net_peer" fn peer(c: Conn, out: u8[>..]&) -> i64;

// ---------------------------------------------------------------- names

// Appends each address of `host` to `out`, one address on each line.
extern "net_resolve" fn resolve(host: const u8[:], out: u8[>..]&) -> bool;

// Appends the message of the last failure on this thread. A call that
// succeeds does not change the message.
extern "net_error" fn error_into(out: u8[>..]&);
fn error() -> u8[>..] {
    var text: u8[>..] = [];
    error_into(text);
    return text;
}

// Reads until the peer ends the stream, or until `out` holds `limit` bytes.
// Returns false for an error. Then error() gives the reason.
fn recv_all(c: Conn, out: u8[>..]&, limit: i64 = 1 << 30) -> bool {
    while out.len < limit {
        let n = recv(c, out, min(limit - out.len, 16384));
        if n == 0 { return true; }
        if n < 0 { return false; }
    }
    return true;
}
