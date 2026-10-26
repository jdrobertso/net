// Tests for URL parsing and resolution. The tests use no network. The
// resolution tests are the normal and abnormal examples of RFC 3986 §5.4.
//
//   goose url_test.goose

import net from "..";
import net.url;
import std;

var failures = 0;

fn check(what: u8[:], got: u8[:], want: u8[:]) {
    if got != want {
        print("FAIL ", what, ": got \"", got, "\", want \"", want, "\"");
        failures++;
    }
}

fn check_resolve(base: url::Url, ref: u8[:], want: u8[:]) {
    var out: u8[>..] = [];
    url::resolve(base, ref, out);
    check(str("resolve ", ref), out, want);
}

fn main() {
    // ---- parsing
    let u, ok = url::parse("HTTPS://user:pw@Example.com:8443/a/b?q=1&r#frag");
    assert(ok);
    check("scheme", u.scheme, "HTTPS");
    assert(url::scheme_is(u, "https"));
    check("userinfo", u.userinfo, "user:pw");
    check("host", u.host, "Example.com");
    assert(u.port == 8443);
    check("path", u.path, "/a/b");
    check("query", u.query, "q=1&r");
    check("fragment", u.fragment, "frag");
    check("round trip", str(u), "HTTPS://user:pw@Example.com:8443/a/b?q=1&r#frag");

    let v6, ok6 = url::parse("http://[::1]:8080/x");
    assert(ok6 && v6.ipv6 && v6.port == 8080);
    check("v6 host", v6.host, "::1");
    var hosthdr: u8[>..] = [];
    url::format_host(hosthdr, v6);
    check("v6 Host header", hosthdr, "[::1]:8080");

    let bare, okb = url::parse("http://example.com");
    assert(okb && bare.port == -1 && url::port_or_default(bare) == 80);
    var target: u8[>..] = [];
    url::format_target(target, bare);
    check("empty path target", target, "/");

    let _, bad_port = url::parse("http://example.com:99999/");
    assert(!bad_port);
    let _, bad_v6 = url::parse("http://[::1/");
    assert(!bad_v6);

    let rel, okr = url::parse("../x?y");
    assert(okr && !rel.has_scheme && !rel.has_authority);
    check("relative path", rel.path, "../x");

    // ---- resolution: RFC 3986 §5.4.1, normal examples
    let b, okbase = url::parse("http://a/b/c/d;p?q");
    assert(okbase);
    check_resolve(b, "g:h", "g:h");
    check_resolve(b, "g", "http://a/b/c/g");
    check_resolve(b, "./g", "http://a/b/c/g");
    check_resolve(b, "g/", "http://a/b/c/g/");
    check_resolve(b, "/g", "http://a/g");
    check_resolve(b, "//g", "http://g");
    check_resolve(b, "?y", "http://a/b/c/d;p?y");
    check_resolve(b, "g?y", "http://a/b/c/g?y");
    check_resolve(b, "#s", "http://a/b/c/d;p?q#s");
    check_resolve(b, "g#s", "http://a/b/c/g#s");
    check_resolve(b, "g?y#s", "http://a/b/c/g?y#s");
    check_resolve(b, ";x", "http://a/b/c/;x");
    check_resolve(b, "g;x", "http://a/b/c/g;x");
    check_resolve(b, "g;x?y#s", "http://a/b/c/g;x?y#s");
    check_resolve(b, "", "http://a/b/c/d;p?q");
    check_resolve(b, ".", "http://a/b/c/");
    check_resolve(b, "./", "http://a/b/c/");
    check_resolve(b, "..", "http://a/b/");
    check_resolve(b, "../", "http://a/b/");
    check_resolve(b, "../g", "http://a/b/g");
    check_resolve(b, "../..", "http://a/");
    check_resolve(b, "../../", "http://a/");
    check_resolve(b, "../../g", "http://a/g");

    // RFC 3986 §5.4.2, abnormal examples
    check_resolve(b, "../../../g", "http://a/g");
    check_resolve(b, "../../../../g", "http://a/g");
    check_resolve(b, "/./g", "http://a/g");
    check_resolve(b, "/../g", "http://a/g");
    check_resolve(b, "g.", "http://a/b/c/g.");
    check_resolve(b, ".g", "http://a/b/c/.g");
    check_resolve(b, "g..", "http://a/b/c/g..");
    check_resolve(b, "..g", "http://a/b/c/..g");
    check_resolve(b, "./../g", "http://a/b/g");
    check_resolve(b, "./g/.", "http://a/b/c/g/");
    check_resolve(b, "g/./h", "http://a/b/c/g/h");
    check_resolve(b, "g/../h", "http://a/b/c/h");
    check_resolve(b, "g;x=1/./y", "http://a/b/c/g;x=1/y");
    check_resolve(b, "g;x=1/../y", "http://a/b/c/y");
    check_resolve(b, "g?y/./x", "http://a/b/c/g?y/./x");
    check_resolve(b, "g?y/../x", "http://a/b/c/g?y/../x");
    check_resolve(b, "g#s/./x", "http://a/b/c/g#s/./x");
    check_resolve(b, "g#s/../x", "http://a/b/c/g#s/../x");
    check_resolve(b, "http:g", "http:g");

    // A base URL with an authority and no path.
    let hb, okh = url::parse("https://example.com");
    assert(okh);
    check_resolve(hb, "page.html", "https://example.com/page.html");
    check_resolve(hb, "//cdn.example.com/x.js", "https://cdn.example.com/x.js");

    // ---- percent-encoding, queries and forms
    var enc: u8[>..] = [];
    url::percent_encode(enc, "a b&c/d~é", true);
    check("form encode", enc, "a+b%26c%2Fd~%C3%A9");
    var dec: u8[>..] = [];
    assert(url::percent_decode(dec, enc, true));
    check("form decode", dec, "a b&c/d~é");
    var bad: u8[>..] = [];
    assert(!url::percent_decode(bad, "100%"));
    check("bad escape", bad, "100%");

    var q: u8[>..] = [];
    url::add_param(q, "q", "goose & duck");
    url::add_param(q, "n", "1");
    check("add_param", q, "q=goose+%26+duck&n=1");
    var seen: u8[>..] = [];
    url::each_param("a=1&&b=&c") { name, value => format(seen, name, "=", value, ";"); };
    check("each_param", seen, "a=1;b=;c=;");

    let sp, oksp = url::parse("http://h/a b/é?x=<y>");
    assert(oksp);
    var tgt: u8[>..] = [];
    url::format_target(tgt, sp);
    check("safe target", tgt, "/a%20b/%C3%A9?x=%3Cy%3E");

    // ---- data: URLs
    var d1: u8[>..] = [];
    let t1, ok1 = url::decode_data("data:,Hello%2C%20World!", d1);
    assert(ok1);
    check("data text", d1, "Hello, World!");
    check("data default type", t1, "");
    var d2: u8[>..] = [];
    let t2, ok2 = url::decode_data("data:text/html;base64,PGI+aGk8L2I+", d2);
    assert(ok2);
    check("data base64", d2, "<b>hi</b>");
    check("data type", t2, "text/html");
    var d3: u8[>..] = [];
    let _, ok3 = url::decode_data("data:;base64,aGk", d3);
    assert(ok3);
    check("data base64 without padding", d3, "hi");
    var d4: u8[>..] = [];
    let _, ok4 = url::decode_data("data:text/plain", d4);
    assert(!ok4);

    // ---- IDNA (RFC 3492 §7.1 and common test hosts)
    fn check_idna(host: u8[:], want: u8[:]) {
        var a: u8[>..] = [];
        assert(url::host_to_ascii(a, host));
        check(str("idna ", host), a, want);
    }
    check_idna("Example.COM", "example.com");
    check_idna("münchen.de", "xn--mnchen-3ya.de");
    check_idna("bücher.example", "xn--bcher-kva.example");
    check_idna("例え.テスト", "xn--r8jz45g.xn--zckzah");
    check_idna("ドメイン名例", "xn--eckwd4c7cu47r2wf");

    if failures == 0 { print("url: all passed"); } else { print("url: ", failures, " failed"); exit(1); }
}
