// A cookie jar (RFC 6265). The jar is a builder of text with one cookie on
// each line. Thus the jar is compact, and to save it, write its bytes to a
// file. A line has eight fields, with a tab between each pair:
//
//   domain  host_only  path  secure  http_only  expires  name  value
//
// host_only, secure and http_only are "0" or "1". expires is in Unix
// seconds, or -1 for a session cookie.
//
//   var jar: u8[>..] = [];
//   cookie::store(jar, "id=42; Path=/; Max-Age=3600", u, now);
//   var header: u8[>..] = [];
//   cookie::format_header(header, jar, u, now);    // "id=42"
//
// Limits: the jar does not use the Public Suffix List. It rejects a Domain
// attribute without a dot, for example "com", but it accepts a domain such
// as "co.uk". It ignores SameSite, because SameSite is a browser policy.

namespace cookie;

import std;
import url;

// The fields of one line of the jar, as slices into the jar.
struct Cookie {
    domain: const u8[:],
    host_only: bool,
    path: const u8[:],
    secure: bool,
    http_only: bool,
    expires: i64,
    name: const u8[:],
    value: const u8[:],
}

// Returns the line of the jar that starts at `p`, and the start of the
// next line. Use it in a loop while p < jar.len.
fn line_at(jar: const u8[:], p: i64) -> const u8[:], i64 {
    var e = find(jar[p..], "\n");
    e = if e < 0 { jar.len } else { p + e };
    return jar[p..e], e + 1;
}

// Splits one line of the jar into a Cookie. Returns false if the line is
// not a valid line of a jar.
fn parse_line(line: const u8[:]) -> Cookie, bool {
    var f: const u8[:][8] = [line[0..0]; 8];
    var n = 0;
    var start = 0;
    for i in line.len + 1 {
        if i == line.len || line[i] == '\t' {
            guard n < 8 else { return Cookie { .. }, false; }
            f[n] = line[start..i];
            n++;
            start = i + 1;
        }
    }
    guard n == 8 else { return Cookie { .. }, false; }
    let exp, ok = parse_int(f[5]);
    guard ok else { return Cookie { .. }, false; }
    return Cookie {
        domain: f[0], host_only: f[1] == "1", path: f[2], secure: f[3] == "1",
        http_only: f[4] == "1", expires: exp, name: f[6], value: f[7],
    }, true;
}

// Calls F with each cookie in the jar, and with the line that holds it.
// The slices in the Cookie are valid only during the call of F. To keep a
// cookie, copy its fields, or use line_at and parse_line in a loop.
fn each<F>(jar: const u8[:]) {
    var p = 0;
    while p < jar.len {
        let line, next = line_at(jar, p);
        let c, ok = parse_line(line);
        if ok { F(c, line); }
        p = next;
    }
}

fn format_line(out: u8[>..]&, c: Cookie) {
    format(out, c.domain, "\t", if c.host_only { "1" } else { "0" }, "\t", c.path, "\t",
           if c.secure { "1" } else { "0" }, "\t", if c.http_only { "1" } else { "0" }, "\t",
           c.expires, "\t", c.name, "\t", c.value, "\n");
}

// ---------------------------------------------------------------- matching

fn is_ip(host: u8[:]) -> bool {
    if find(host, ":") >= 0 { return true; }
    for c in host { if !(url::is_digit(c) || c == '.') { return false; } }
    return true;
}

// True if `host` domain-matches `domain` (RFC 6265 §5.1.3).
fn domain_match(host: u8[:], domain: u8[:]) -> bool {
    if url::equal_ci(host, domain) { return true; }
    guard host.len > domain.len && !is_ip(host) else { return false; }
    let tail = host[host.len - domain.len..];
    return host[host.len - domain.len - 1] == '.' && url::equal_ci(tail, domain);
}

// True if `path` path-matches `cookie_path` (RFC 6265 §5.1.4).
fn path_match(path: u8[:], cookie_path: u8[:]) -> bool {
    if path == cookie_path { return true; }
    guard starts_with(path, cookie_path) else { return false; }
    return ends_with(cookie_path, "/") || path[cookie_path.len] == '/';
}

// The default path of a request path (RFC 6265 §5.1.4): the path up to,
// but not including, its last '/'. The result is "/" when that is empty.
fn default_path(path: const u8[:]) -> const u8[:] {
    guard path.len > 0 && path[0] == '/' else { return "/"; }
    let slash = rfind(path, "/");
    if slash <= 0 { return "/"; }
    return path[..slash];
}

fn request_path(u: url::Url) -> const u8[:] { if u.path.len == 0 { "/" } else { u.path } }

// ---------------------------------------------------------------- dates

let MONTHS = "janfebmaraprmayjunjulaugsepoctnovdec";

// Days from 1970-01-01 to a date in the Gregorian calendar.
fn days_from_civil(y_in: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y_in - 1 } else { y_in };
    let era = div_euclid(y, 400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn is_date_char(c: u8) -> bool { url::is_alpha(c) || url::is_digit(c) || c == ':' }

// Parses a cookie date (RFC 6265 §5.1.1) into Unix seconds. The parser
// accepts the usual forms, for example "Wed, 21 Oct 2015 07:28:00 GMT" and
// "Wednesday, 21-Oct-15 07:28:00 GMT".
fn parse_date(s: u8[:]) -> i64, bool {
    var hour = -1;
    var minute = 0;
    var second = 0;
    var day = -1;
    var month = -1;
    var year = -1;
    var i = 0;
    while i < s.len {
        // The delimiters are all the bytes that are not letters, digits or ':'.
        while i < s.len && !is_date_char(s[i]) { i++; }
        let start = i;
        while i < s.len && is_date_char(s[i]) { i++; }
        let tok = s[start..i];
        guard tok.len > 0 else { continue; }
        if hour < 0 && find(tok, ":") > 0 {
            let parts = split(tok, ':');
            if parts.len == 3 {
                let h, ok1 = parse_int(parts[0]);
                let mi, ok2 = parse_int(parts[1]);
                let se, ok3 = parse_int(parts[2]);
                if ok1 && ok2 && ok3 { hour = h; minute = mi; second = se; continue; }
            }
        }
        if url::is_digit(tok[0]) {
            var digits = 0;
            while digits < tok.len && url::is_digit(tok[digits]) { digits++; }
            let v, _ = parse_int(tok[..digits]);
            if day < 0 && digits <= 2 { day = v; continue; }
            if year < 0 && digits >= 2 && digits <= 4 { year = v; continue; }
        }
        if month < 0 && tok.len >= 3 {
            for m in 12 {
                if url::equal_ci(tok[..3], MONTHS[m * 3..m * 3 + 3]) { month = m + 1; }
            }
        }
    }
    if year >= 70 && year <= 99 { year += 1900; }
    if year >= 0 && year <= 69 { year += 2000; }
    guard hour >= 0 && day >= 1 && day <= 31 && month >= 1 && year >= 1601 &&
          hour <= 23 && minute <= 59 && second <= 59 else { return 0, false; }
    return days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second, true;
}

// ---------------------------------------------------------------- the jar

// Puts the cookie of one Set-Cookie header value into the jar (RFC 6265
// §5.2 and §5.3). `u` is the URL of the request that got the header. `now`
// is the time in Unix seconds. The function ignores a cookie that is not
// valid or not permitted for `u`. A cookie with the same name, domain and
// path replaces the old cookie. An expired cookie removes the old cookie.
fn store(jar: u8[>..]&, set_cookie: const u8[:], u: url::Url, now: i64) {
    let semi = find(set_cookie, ";");
    let pair = if semi >= 0 { set_cookie[..semi] } else { set_cookie };
    let eq = find(pair, "=");
    guard eq > 0 else { return; }
    let name = trim(pair[..eq]);
    let value = trim(pair[eq + 1..]);
    guard name.len > 0 else { return; }
    for c in set_cookie { guard c != '\t' && c != '\n' && c != '\r' else { return; } }

    var expires = -1;
    var max_age_set = false;
    var domain = set_cookie[0..0];
    var path = set_cookie[0..0];
    var secure = false;
    var http_only = false;
    // A plain loop, not each_split, because domain and path keep slices of
    // the attributes after the loop.
    var p = if semi >= 0 { semi + 1 } else { set_cookie.len };
    while p < set_cookie.len {
        var e = find(set_cookie[p..], ";");
        e = if e < 0 { set_cookie.len } else { p + e };
        let av = set_cookie[p..e];
        p = e + 1;
        let aeq = find(av, "=");
        let key = trim(if aeq >= 0 { av[..aeq] } else { av });
        let val = trim(if aeq >= 0 { av[aeq + 1..] } else { av[av.len..] });
        if url::equal_ci(key, "expires") && !max_age_set {
            let t, ok = parse_date(val);
            if ok { expires = t; }
        } else if url::equal_ci(key, "max-age") {
            let d, ok = parse_int(val);
            if ok {
                // Zero or less means "expired now". Any time in the past has that effect.
                expires = if d <= 0 { 0 } else { now + d };
                max_age_set = true;
            }
        } else if url::equal_ci(key, "domain") {
            domain = if val.len > 0 && val[0] == '.' { val[1..] } else { val };
        } else if url::equal_ci(key, "path") {
            if val.len > 0 && val[0] == '/' { path = val; }
        } else if url::equal_ci(key, "secure") {
            secure = true;
        } else if url::equal_ci(key, "httponly") {
            http_only = true;
        }
    }

    // The final domain and path come from the header or from the URL. The
    // two sources have different lifetimes, so copy the result.
    let host_only = domain.len == 0;
    var dom: u8[>..] = [];
    if host_only {
        for c in u.host { dom.push(url::lower(c)); }
    } else {
        guard domain_match(u.host, domain) else { return; }
        guard find(domain, ".") > 0 || url::equal_ci(domain, u.host) else { return; }
        for c in domain { dom.push(url::lower(c)); }
    }
    var cpath: u8[>..] = [];
    if path.len == 0 { cpath.append(default_path(u.path)); } else { cpath.append(path); }
    // A cookie with Secure can come only from a secure URL.
    guard !secure || url::scheme_is(u, "https") else { return; }

    var next: u8[>..] = [];
    each(jar) { c, line =>
        let same = c.name == name && url::equal_ci(c.domain, dom) && c.path == cpath;
        let expired = c.expires >= 0 && c.expires <= now;
        if !same && !expired { next.append(line); next.push('\n'); }
    };
    if expires < 0 || expires > now {
        format_line(next, Cookie {
            domain: dom, host_only: host_only, path: cpath, secure: secure,
            http_only: http_only, expires: expires, name: name, value: value,
        });
    }
    jar.clear();
    jar.append(next);
}

// One cookie for a Cookie header, before the sort.
struct Match { path_len: i64, order: i64, name: const u8[:], value: const u8[:] }

// Appends the value of a Cookie request header for `u`: "a=1; b=2". The
// cookies with longer paths come first (RFC 6265 §5.4). Appends nothing if
// no cookie matches.
fn format_header(out: u8[>..]&, jar: const u8[:], u: url::Url, now: i64) {
    var found: Match[>..] = [];
    let https = url::scheme_is(u, "https");
    let path = request_path(u);
    var p = 0;
    while p < jar.len {
        let line, next = line_at(jar, p);
        p = next;
        let c, ok = parse_line(line);
        guard ok else { continue; }
        let host_ok = if c.host_only { url::equal_ci(u.host, c.domain) } else { domain_match(u.host, c.domain) };
        let live = c.expires < 0 || c.expires > now;
        if host_ok && live && path_match(path, c.path) && (!c.secure || https) {
            found.push(Match { path_len: c.path.len, order: found.len, name: c.name, value: c.value });
        }
    }
    sort(found) { a, b => a.path_len > b.path_len || (a.path_len == b.path_len && a.order < b.order) };
    for m, i in found {
        if i > 0 { out.append("; "); }
        format(out, m.name, "=", m.value);
    }
}

// Appends the cookies of the jar that are not session cookies and are not
// expired. Use it to save a jar to a file.
fn persistent(out: u8[>..]&, jar: const u8[:], now: i64) {
    each(jar) { c, line => if c.expires > now { out.append(line); out.push('\n'); } };
}
