// Tests for the socket layer on the local machine. One thread is the
// client and the server: the connect completes in the backlog of the
// listener before the accept.
//
//   goose net_test.goose

import net from "..";
import std;

var failures = 0;

fn fail(what: u8[:]) {
    print("FAIL ", what, ": ", net::error());
    failures++;
}

fn main() {
    let l = net::listen("127.0.0.1", 0);
    guard net::ok(l) else { fail("listen"); exit(1); }
    let port = net::local_port(l);
    if port <= 0 { fail("local_port"); }

    let c = net::connect("127.0.0.1", port, false, 5000);
    guard net::ok(c) else { fail("connect"); exit(1); }
    let s = net::accept(l, 5000);
    guard net::ok(s) else { fail("accept"); exit(1); }

    var who: u8[>..] = [];
    if net::peer(s, who) <= 0 || who != "127.0.0.1" { fail(str("peer gave ", who)); }

    // Both directions, with more than one recv buffer of data.
    var big: u8[>..] = [];
    for i in 100000 { big.push((i % 251) as! u8); }
    if !net::send(c, big) { fail("send"); }
    var got: u8[>..] = [];
    while got.len < big.len { if net::recv(s, got) <= 0 { fail("recv"); break; } }
    if got != big { fail("the server did not get the same bytes"); }

    if !net::send(s, "pong") { fail("send back"); }
    var back: u8[>..] = [];
    if net::recv(c, back) <= 0 || back != "pong" { fail("recv back"); }

    // After the server closes, the client sees the end of the stream.
    net::close(s);
    var rest: u8[>..] = [];
    if net::recv(c, rest) != 0 { fail("end of stream"); }

    // A closed Conn fails safely.
    net::close(c);
    if net::send(c, "x") { fail("send on a closed Conn"); }
    let e = net::error();
    if !starts_with(e, "connection ") { fail(str("closed Conn message: ", e)); }

    // The accept time limit.
    let t = net::accept(l, 100);
    if net::ok(t) { fail("accept with nobody connecting"); }
    net::close(l);

    // A port where nothing listens refuses the connection.
    let r = net::connect("127.0.0.1", port, false, 2000);
    if net::ok(r) { fail("connect to a closed port"); }

    if failures == 0 { print("net: all passed"); } else { print("net: ", failures, " failed"); exit(1); }
}
