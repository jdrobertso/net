// URLs (RFC 3986). This module splits a URL into its parts. It also
// resolves a reference against a base URL, as for the Location header of
// a redirect or for the links in a page.
//
// A Url is a set of slices into its source text. Thus parse copies no
// bytes, and a Url is valid only while its source text is valid. To make
// a new URL, resolve writes text into a builder that the caller owns.
// To get the parts of the new URL, parse that text.
//
//   let u, ok = url::parse("https://example.com:8443/a/b?q=1#top");
//   u.host == "example.com", u.port == 8443, u.path == "/a/b", u.query == "q=1"
//
//   var next: u8[>..] = [];
//   url::resolve(u, "../c?x", next);       // https://example.com:8443/c?x

namespace url;

import std;
import base64;

struct Url {
    scheme: const u8[:],       // as the text gives it. Use scheme_is to compare.
    authority: const u8[:],    // userinfo@host:port, as the text gives it
    userinfo: const u8[:],
    host: const u8[:],         // for an IPv6 literal, the address without the brackets
    port: i64,                 // -1 when the URL has no port
    path: const u8[:],
    query: const u8[:],        // without the '?'
    fragment: const u8[:],     // without the '#'
    has_scheme: bool,
    has_authority: bool,       // true when "//" is in the text, also with no text after it
    has_query: bool,           // true when "?" is in the text, also with no text after it
    has_fragment: bool,
    ipv6: bool,                // true when the host is an IPv6 literal in brackets
}

// ---------------------------------------------------------------- parsing

fn is_alpha(c: u8) -> bool { (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
fn is_digit(c: u8) -> bool { c >= '0' && c <= '9' }
fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// Compares two strings for equality, with no difference between ASCII
// upper case and lower case. Use it for schemes, hosts and header names.
fn equal_ci(a: u8[:], b: u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len { if lower(a[i]) != lower(b[i]) { return false; } }
    return true;
}

fn scheme_is(u: Url, s: u8[:]) -> bool { equal_ci(u.scheme, s) }

// Returns the length of the scheme at the start of s, or 0 if there is no
// scheme. A scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), with a ':'
// after it.
fn scheme_len(s: u8[:]) -> i64 {
    guard s.len > 0 && is_alpha(s[0]) else { return 0; }
    var i = 1;
    while i < s.len {
        let c = s[i];
        if c == ':' { return i; }
        guard is_alpha(c) || is_digit(c) || c == '+' || c == '-' || c == '.' else { return 0; }
        i++;
    }
    return 0;
}

// Splits a URI reference. The reference can be absolute ("https://h/p") or
// relative ("../p?q", "//h/p", "#f"). The result is false only when the
// authority is not valid: a bad port, or an IPv6 bracket with no end. The
// caller must check if the result is a URL that it can get (has_scheme, host).
fn parse(text: const u8[:]) -> Url, bool {
    var u = Url { port: -1, .. };
    var rest = text;

    // Remove the fragment and the query from the end first. Neither one can contain the other.
    let hash = find(rest, "#");
    if hash >= 0 { u.fragment = rest[hash + 1..]; u.has_fragment = true; rest = rest[..hash]; }
    let q = find(rest, "?");
    if q >= 0 { u.query = rest[q + 1..]; u.has_query = true; rest = rest[..q]; }

    let sl = scheme_len(rest);
    if sl > 0 { u.scheme = rest[..sl]; u.has_scheme = true; rest = rest[sl + 1..]; }

    if starts_with(rest, "//") {
        rest = rest[2..];
        var end = 0;
        while end < rest.len && rest[end] != '/' { end++; }
        u.authority = rest[..end];
        u.has_authority = true;
        rest = rest[end..];
        guard split_authority(u) else { return u, false; }
    }
    u.path = rest;
    return u, true;
}

// Splits userinfo@host:port. The host can be an IPv6 literal, "[v6]".
fn split_authority(u: Url&) -> bool {
    var a = u.authority;
    let at = rfind(a, "@");
    if at >= 0 { u.userinfo = a[..at]; a = a[at + 1..]; }
    var port_text = a[a.len..];
    if a.len > 0 && a[0] == '[' {
        let close = find(a, "]");
        guard close > 0 else { return false; }
        u.host = a[1..close];
        u.ipv6 = true;
        let after = a[close + 1..];
        if after.len > 0 {
            guard after[0] == ':' else { return false; }
            port_text = after[1..];
        }
    } else {
        let colon = rfind(a, ":");
        if colon >= 0 { u.host = a[..colon]; port_text = a[colon + 1..]; } else { u.host = a; }
    }
    // "host:" with no digits is valid. It means that the URL has no port.
    if port_text.len > 0 {
        for c in port_text { guard is_digit(c) else { return false; } }
        let p, ok = parse_int(port_text);
        guard ok && p <= 65535 else { return false; }
        u.port = p;
    }
    return true;
}

// Returns the port for a connection: the port in the URL, or else the
// default port of its scheme.
fn port_or_default(u: Url) -> i64 {
    if u.port >= 0 { return u.port; }
    if scheme_is(u, "https") || scheme_is(u, "wss") { return 443; }
    if scheme_is(u, "http") || scheme_is(u, "ws") { return 80; }
    return -1;
}

// ---------------------------------------------------------------- writing

// Writes the full URL as text, with the parts that parse found. This is a
// `format` overload. Thus print, str and format show a Url as its URL.
fn format(out: u8[>..]&, u: Url) {
    if u.has_scheme { out.append(u.scheme); out.push(':'); }
    if u.has_authority { out.append("//"); out.append(u.authority); }
    out.append(u.path);
    if u.has_query { out.push('?'); out.append(u.query); }
    if u.has_fragment { out.push('#'); out.append(u.fragment); }
}

// Writes the target of an HTTP request line: the path ("/" if the path is
// empty) and the query. The function encodes the bytes that a request line
// cannot hold (see append_target_safe).
fn format_target(out: u8[>..]&, u: Url) {
    if u.path.len == 0 { out.push('/'); } else { append_target_safe(out, u.path); }
    if u.has_query { out.push('?'); append_target_safe(out, u.query); }
}

// Writes the value of a Host header: the host, and the port if the URL has one.
fn format_host(out: u8[>..]&, u: Url) {
    if u.ipv6 { out.push('['); out.append(u.host); out.push(']'); } else { out.append(u.host); }
    if u.port >= 0 { out.push(':'); ::format(out, u.port); }
}

// ---------------------------------------------------------------- resolving

// Appends `path` without its "." and ".." segments (RFC 3986 §5.2.4). If
// the path ends with one of these segments, the result keeps a trailing
// slash. For example, "/a/b/.." becomes "/a/". The function removes a ".."
// that is above the root.
fn remove_dots(out: u8[>..]&, path: const u8[:]) {
    guard path.len > 0 && path[0] == '/' else { out.append(path); return; }
    var segs: const u8[:][>..<] = [];
    var trailing = false;
    let parts = split(path[1..], '/');
    for p, i in parts {
        let last = i == parts.len - 1;
        if p == "." {
            if last { trailing = true; }
        } else if p == ".." {
            if segs.len > 0 { segs.pop(); }
            if last { trailing = true; }
        } else {
            segs.push(p);
        }
    }
    for s in segs { out.push('/'); out.append(s); }
    if trailing || segs.len == 0 { out.push('/'); }
}

// Appends the URL that `ref` refers to (RFC 3986 §5.2.2). `ref` is a
// reference from a document or from a Location header at `base`. Make sure
// that `base` is an absolute URL.
fn resolve(base: Url, ref: const u8[:], out: u8[>..]&) {
    let r, ok = parse(trim(ref));
    if !ok || r.has_scheme {
        // The reference is absolute, or parse cannot split it. Remove only its dot segments.
        if !ok { out.append(trim(ref)); return; }
        out.append(r.scheme); out.push(':');
        if r.has_authority { out.append("//"); out.append(r.authority); }
        remove_dots(out, r.path);
        if r.has_query { out.push('?'); out.append(r.query); }
        if r.has_fragment { out.push('#'); out.append(r.fragment); }
        return;
    }

    out.append(base.scheme); out.push(':');
    if r.has_authority {
        out.append("//"); out.append(r.authority);
        remove_dots(out, r.path);
        if r.has_query { out.push('?'); out.append(r.query); }
    } else {
        if base.has_authority { out.append("//"); out.append(base.authority); }
        if r.path.len == 0 {
            out.append(base.path);
            if r.has_query { out.push('?'); out.append(r.query); }
            else if base.has_query { out.push('?'); out.append(base.query); }
        } else {
            if r.path[0] == '/' {
                remove_dots(out, r.path);
            } else {
                // Merge the paths: the base path up to its last '/', then the reference.
                var merged: u8[>..] = [];
                if base.has_authority && base.path.len == 0 {
                    merged.push('/');
                } else {
                    let slash = rfind(base.path, "/");
                    if slash >= 0 { merged.append(base.path[..slash + 1]); }
                }
                merged.append(r.path);
                remove_dots(out, merged);
            }
            if r.has_query { out.push('?'); out.append(r.query); }
        }
    }
    if r.has_fragment { out.push('#'); out.append(r.fragment); }
}

// ---------------------------------------------------------------- percent-encoding

let HEX = "0123456789ABCDEF";

fn hex_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// True for the bytes that a URL component can hold with no encoding (RFC 3986 §2.3).
fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

fn push_escape(out: u8[>..]&, c: u8) {
    out.push('%');
    out.push(HEX[c >> 4]);
    out.push(HEX[c & 15]);
}

// Appends `s`, with each byte that is not unreserved as %XX. Use it for one
// component, for example a path segment or a query value. With `form`, a
// space becomes '+', as in application/x-www-form-urlencoded.
fn percent_encode(out: u8[>..]&, s: u8[:], form: bool = false) {
    for c in s {
        if is_unreserved(c) { out.push(c); }
        else if form && c == ' ' { out.push('+'); }
        else { push_escape(out, c); }
    }
}

// Appends `s` with each %XX decoded. With `form`, '+' becomes a space.
// Returns false if `s` has a '%' without two hex digits after it. The
// function copies that '%' with no change.
fn percent_decode(out: u8[>..]&, s: u8[:], form: bool = false) -> bool {
    var ok = true;
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '%' && i + 2 < s.len {
            let h = hex_value(s[i + 1]);
            let l = hex_value(s[i + 2]);
            if h >= 0 && l >= 0 {
                out.push((h * 16 + l) as! u8);
                i += 3;
                continue;
            }
        }
        if c == '%' { ok = false; }
        out.push(if form && c == '+' { ' ' } else { c });
        i++;
    }
    return ok;
}

// Appends `s` for an HTTP request line. The function encodes only the
// bytes that cannot be in a request target: controls, the space, non-ASCII
// bytes and "<>`{}. It keeps all other bytes, %XX escapes too. Thus a URL
// with non-ASCII text, for example from an HTML link, gives a valid request.
fn append_target_safe(out: u8[>..]&, s: u8[:]) {
    for c in s {
        if c <= ' ' || c >= 0x7f || c == '"' || c == '<' || c == '>' || c == '`' || c == '{' || c == '}' {
            push_escape(out, c);
        } else {
            out.push(c);
        }
    }
}

// ---------------------------------------------------------------- queries and forms

// Calls F with the name and the value of each parameter in a query or a
// form body, for example "a=1&b=2". The name and the value are raw slices.
// To decode them, use percent_decode with `form`.
fn each_param<F>(query: u8[:]) {
    each_split(query, '&') {
        if it.len > 0 {
            let eq = find(it, "=");
            if eq >= 0 { F(it[..eq], it[eq + 1..]); } else { F(it, it[it.len..]); }
        }
    };
}

// Appends one encoded name=value parameter to a query or a form body in
// `out`. If `out` is not empty, the function writes '&' first. Thus `out`
// must hold only the query, without the '?'.
fn add_param(out: u8[>..]&, name: u8[:], value: u8[:]) {
    if out.len > 0 { out.push('&'); }
    percent_encode(out, name, true);
    out.push('=');
    percent_encode(out, value, true);
}

// ---------------------------------------------------------------- data: URLs

// Decodes a data: URL (RFC 2397) and appends its bytes to `out`. Returns
// the media type as the URL gives it, and true. An empty media type means
// "text/plain;charset=US-ASCII". A media type that starts with ';' means
// text/plain with those parameters. Returns false when `text` is not a
// valid data: URL.
fn decode_data(text: const u8[:], out: u8[>..]&) -> const u8[:], bool {
    guard text.len >= 5 && equal_ci(text[..5], "data:") else { return text[0..0], false; }
    var rest = text[5..];
    // A fragment is not part of the data.
    let hash = find(rest, "#");
    if hash >= 0 { rest = rest[..hash]; }
    let comma = find(rest, ",");
    guard comma >= 0 else { return text[0..0], false; }
    var mtype = trim(rest[..comma]);
    let payload = rest[comma + 1..];
    var b64 = false;
    if mtype.len >= 7 && equal_ci(mtype[mtype.len - 7..], ";base64") {
        b64 = true;
        mtype = trim(mtype[..mtype.len - 7]);
    }
    if !b64 {
        percent_decode(out, payload);
        return mtype, true;
    }
    // Base64 text can contain escapes and white space. Remove them, and add
    // the '=' padding if the URL has none.
    var decoded: u8[>..] = [];
    percent_decode(decoded, payload);
    var clean: u8[>..] = [];
    for c in decoded { if !is_space(c) { clean.push(c); } }
    while clean.len % 4 != 0 { clean.push('='); }
    // base64::decode can shrink its output, so it gets a builder of its own.
    var bytes: u8[>..] = [];
    guard base64::decode(bytes, clean) else { return text[0..0], false; }
    out.append(bytes);
    return mtype, true;
}

// ---------------------------------------------------------------- IDNA

// Appends the Punycode form of one label (RFC 3492). `cps` are its code points.
fn punycode(out: u8[>..]&, cps: i64[:]) {
    let BASE = 36;
    let TMIN = 1;
    let TMAX = 26;

    fn digit(d: i64) -> u8 { if d < 26 { ('a' + d) as! u8 } else { ('0' + d - 26) as! u8 } }

    fn adapt(delta_in: i64, points: i64, first: bool) -> i64 {
        var delta = if first { delta_in / 700 } else { delta_in / 2 };
        delta += delta / points;
        var k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 { delta /= BASE - TMIN; k += BASE; }
        return k + (BASE - TMIN + 1) * delta / (delta + 38);
    }

    var basic = 0;
    for c in cps { if c < 0x80 { out.push(lower(c as! u8)); basic++; } }
    if basic > 0 { out.push('-'); }

    var n = 128;
    var delta = 0;
    var bias = 72;
    var h = basic;
    while h < cps.len {
        var m = 0x7fffffff;
        for c in cps { if c >= n && c < m { m = c; } }
        delta += (m - n) * (h + 1);
        n = m;
        for c in cps {
            if c < n { delta++; }
            if c == n {
                var q = delta;
                var k = BASE;
                loop {
                    let t = if k <= bias { TMIN } else if k >= bias + TMAX { TMAX } else { k - bias };
                    if q < t { break; }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, h + 1, h == basic);
                delta = 0;
                h++;
            }
        }
        delta++;
        n++;
    }
}

// Appends the ASCII form of `host` (IDNA, RFC 5891), for DNS and for the
// Host header. ASCII letters become lower case. Each label with non-ASCII
// characters becomes "xn--" and its Punycode. This is a basic form of IDNA.
// It does no Unicode normalization or mapping (UTS #46). Returns false for
// a host that is not valid UTF-8, or for a label longer than 63 bytes.
fn host_to_ascii(out: u8[>..]&, host: u8[:]) -> bool {
    var first = true;
    var ok = true;
    each_split(host, '.') {
        if !first { out.push('.'); }
        first = false;
        var ascii = true;
        for c in it { if c >= 0x80 { ascii = false; } }
        let start = out.len;
        if ascii {
            for c in it { out.push(lower(c)); }
        } else {
            var cps: i64[>..] = [];
            each_utf8(it) { if it == 0xFFFD { ok = false; } cps.push(it); };
            out.append("xn--");
            punycode(out, cps);
        }
        if out.len - start > 63 { ok = false; }
    };
    return ok;
}
