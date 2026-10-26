// This example uses only the lowest layer: a TLS connection and a request
// that the example writes itself.
//
//   goose raw.goose -- [host]

import net from "..";
import std;
import os;

fn main() {
    let a = args();
    let host = if a.len > 1 { a[1] } else { "example.com" };

    var addrs: u8[>..] = [];
    if net::resolve(host, addrs) { print(host, " is ", trim(addrs)); }

    let c = net::connect(host, 443, true);
    guard net::ok(c) else { print("connect failed: ", net::error()); exit(1); }
    let req = str("GET / HTTP/1.1\r\nHost: ", host, "\r\nConnection: close\r\n\r\n");
    guard net::send(c, req) else { print("send failed: ", net::error()); exit(1); }
    var reply: u8[>..] = [];
    let ok = net::recv_all(c, reply);
    net::close(c);
    guard ok else { print("recv failed: ", net::error()); exit(1); }
    let eol = find(reply, "\r\n");
    print(reply.len, " bytes; ", if eol >= 0 { reply[..eol] } else { reply[..] });
}
