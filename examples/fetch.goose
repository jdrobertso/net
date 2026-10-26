// A small curl. It gets a URL with net.http. Then it prints the status, the
// count of redirects, the headers and the start of the body.
//
//   goose fetch.goose -- https://example.com/ [--body] [--save out.html]

import net from "..";
import net.http;
import std;
import os;

fn main() {
    let a = args();
    var target: const u8[:] = "https://example.com/";
    var show_body = false;
    var save: const u8[:] = "";
    var i = 1;
    while i < a.len {
        if a[i] == "--body" { show_body = true; }
        else if a[i] == "--save" && i + 1 < a.len { i++; save = a[i]; }
        else { target = a[i]; }
        i++;
    }

    let t0 = clock();
    let r = http::get(target);
    let ms = (clock() - t0) * 1000.0;
    guard http::ok(r) else { print("error: ", http::error(r)); exit(1); }

    print(r.status, " ", http::reason(r), "  ", http::final_url(r));
    if r.redirects > 0 { print("(after ", r.redirects, " redirect", if r.redirects == 1 { "" } else { "s" }, ")"); }
    http::each_header(r) { name, value => print("  ", name, ": ", value); };
    let b = http::body(r);
    var took: u8[>..] = [];
    format_flt(took, ms, 0);
    print(b.len, " bytes of body in ", took, " ms");
    if show_body { print(b); }
    else if b.len > 0 { print("---\n", b[..min(b.len, 300)], if b.len > 300 { "..." } else { "" }); }
    if save.len > 0 {
        if write_file(save, b) { print("saved to ", save); } else { print("cannot write ", save); }
    }
}
