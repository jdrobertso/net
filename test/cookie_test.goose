// Tests for the cookie jar. The tests use no network.
//
//   goose cookie_test.goose

import net from "..";
import net.url;
import net.cookie;
import std;

var failures = 0;

fn check(what: u8[:], got: u8[:], want: u8[:]) {
    if got != want {
        print("FAIL ", what, ": got \"", got, "\", want \"", want, "\"");
        failures++;
    }
}

fn header_for(jar: u8[:], target: u8[:], now: i64) -> u8[>..] {
    let u, ok = url::parse(target);
    assert(ok);
    var h: u8[>..] = [];
    cookie::format_header(h, jar, u, now);
    return h;
}

fn main() {
    let now = 1700000000;

    // ---- dates
    let t1, ok1 = cookie::parse_date("Wed, 21 Oct 2015 07:28:00 GMT");
    if !ok1 || t1 != 1445412480 { print("FAIL date 1: ", t1); failures++; }
    let t2, ok2 = cookie::parse_date("Wednesday, 21-Oct-15 07:28:00 GMT");
    if !ok2 || t2 != 1445412480 { print("FAIL date 2: ", t2); failures++; }
    let _, ok3 = cookie::parse_date("not a date");
    if ok3 { print("FAIL date 3"); failures++; }

    // ---- storing and sending
    var jar: u8[>..] = [];
    let a, oka = url::parse("https://www.example.com/shop/cart");
    assert(oka);
    cookie::store(jar, "sid=abc; Path=/; Secure; HttpOnly", a, now);
    cookie::store(jar, "cart=3", a, now);                                   // the default path is /shop
    cookie::store(jar, "lang=en; Domain=.example.com; Path=/", a, now);
    cookie::store(jar, "bad=1; Domain=other.com", a, now);                  // not this domain
    cookie::store(jar, "tld=1; Domain=com", a, now);                        // no dot
    cookie::store(jar, "novalue", a, now);                                  // no '='

    check("cart page", header_for(jar, "https://www.example.com/shop/cart", now), "cart=3; sid=abc; lang=en");
    check("root page", header_for(jar, "https://www.example.com/", now), "sid=abc; lang=en");
    check("plain http", header_for(jar, "http://www.example.com/shop/x", now), "cart=3; lang=en");
    check("subdomain", header_for(jar, "https://api.example.com/", now), "lang=en");
    check("other host", header_for(jar, "https://example.org/", now), "");
    check("path prefix", header_for(jar, "https://www.example.com/shopping", now), "sid=abc; lang=en");

    // A new cookie with the same name, domain and path replaces the old one.
    cookie::store(jar, "cart=4", a, now);
    check("replace", header_for(jar, "https://www.example.com/shop/", now), "cart=4; sid=abc; lang=en");

    // Max-Age=0 removes the cookie. Max-Age has priority over Expires.
    cookie::store(jar, "cart=0; Max-Age=0", a, now);
    check("remove", header_for(jar, "https://www.example.com/shop/", now), "sid=abc; lang=en");
    cookie::store(jar, "tmp=1; Path=/; Max-Age=60; Expires=Wed, 21 Oct 2015 07:28:00 GMT", a, now);
    check("max-age priority", header_for(jar, "https://www.example.com/", now), "sid=abc; lang=en; tmp=1");
    check("expiry", header_for(jar, "https://www.example.com/", now + 61), "sid=abc; lang=en");

    // A Secure cookie cannot come from plain http.
    let h, okh = url::parse("http://www.example.com/");
    assert(okh);
    cookie::store(jar, "evil=1; Secure", h, now);
    check("secure from http", header_for(jar, "https://www.example.com/", now), "sid=abc; lang=en; tmp=1");

    // Only the cookies with an expiry time go to the saved form.
    var saved: u8[>..] = [];
    cookie::persistent(saved, jar, now);
    check("persistent", saved, str("www.example.com\t1\t/\t0\t0\t", now + 60, "\ttmp\t1\n"));

    if failures == 0 { print("cookie: all passed"); } else { print("cookie: ", failures, " failed"); exit(1); }
}
