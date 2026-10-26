// A Session: several requests on one kept-alive connection, a cookie jar,
// and a streamed download with progress.
//
//   goose session.goose

import net from "..";
import net.http;
import std;
import os;

fn main() {
    var s = http::session();

    // The server sets two cookies and redirects to a page that shows the
    // cookies that it got back.
    let r = http::get(s, "https://httpbin.org/cookies/set?flavor=goose&size=large");
    print(r.status, " after ", r.redirects, " redirect: ", trim(http::body(r)));

    // Five requests to one host. The first one connects. The others use the
    // connection in the pool, so they are faster.
    for i in 5 {
        let t = clock();
        let q = http::get(s, str("https://httpbin.org/get?n=", i));
        var ms: u8[>..] = [];
        format_flt(ms, (clock() - t) * 1000.0, 0);
        print("request ", i, ": ", q.status, " in ", ms, " ms, ", s.pool.len, " connection(s) in the pool");
    }

    // A streamed download: the body arrives in parts, and only the count of
    // bytes stays in memory.
    var got = 0;
    var parts = 0;
    let d = http::stream(s, "GET", "https://httpbin.org/bytes/200000") { chunk, total =>
        got += chunk.len;
        parts++;
    };
    print("stream: ", d.status, ", ", got, " bytes in ", parts, " parts, body kept: ", http::body(d).len);

    http::close(s);
}
