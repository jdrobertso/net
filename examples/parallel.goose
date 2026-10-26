// Gets several pages at the same time with the client that does not block.
// The main thread continues to run while the requests are in flight, as a
// frame loop would.
//
//   goose build parallel.goose && parallel [url ...]

import net from "..";
import net.http;
import net.client;
import std;
import os;

fn ms_since(t: f64) -> u8[>..] {
    var s: u8[>..] = [];
    format_flt(s, (clock() - t) * 1000.0, 0);
    return s;
}

fn main() {
    let a = args();
    var c = http::client();
    let t0 = clock();
    if a.len > 1 {
        for i in 1..a.len { http::submit(c, "GET", a[i]); }
    } else {
        for u in ["https://example.com/", "https://en.wikipedia.org/wiki/Goose",
                  "https://github.com/", "https://www.google.com/"] {
            http::submit(c, "GET", u);
        }
    }

    var frames = 0;
    while http::pending(c) > 0 {
        let id, r = http::poll(c);
        if id < 0 {
            // No request is complete. Here a program would draw a frame.
            frames++;
            sleep_ms(1);
            continue;
        }
        if http::ok(r) {
            print("request ", id, ": ", r.status, " ", http::final_url(r), ", ",
                  http::body(r).len, " bytes, at ", ms_since(t0), " ms");
        } else {
            print("request ", id, ": error: ", http::error(r));
        }
    }
    print("all done at ", ms_since(t0), " ms. The main thread ran ", frames, " frames while it waited.");
    http::close(c);
}
