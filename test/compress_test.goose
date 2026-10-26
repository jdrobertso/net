// Tests for the gzip, zlib and DEFLATE decoders. The test data comes from
// make_fixtures.py, which uses the zlib of Python as the reference encoder.
// Git keeps the small cases in data/. The large cases in data/gen/ exist
// only after make_fixtures.py runs. Without them, the test skips them and
// says so.
//
//   goose compress_test.goose

import net from "..";
import net.compress;
import std;
import os;

var failures = 0;

fn fail(what: u8[:]) {
    print("FAIL ", what);
    failures++;
}

fn load(name: u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    if !read_file(str("data/", name), d) { abort(str("cannot read data/", name, ". Run make_fixtures.py.")); }
    return d;
}

// Decodes the three forms of one case and compares each result with the
// source. `name` includes the directory below data/, for example "gen/words".
fn check_case(name: u8[:]) {
    let want = load(str(name, ".bin"));
    let gz = load(str(name, ".gz"));
    let zz = load(str(name, ".zz"));
    let raw = load(str(name, ".raw"));

    var a: u8[>..] = [];
    let ok1, why1 = compress::gunzip(gz, a);
    if !ok1 || a != want { fail(str(name, ".gz: ", why1, " (", a.len, " of ", want.len, " bytes)")); }

    var b: u8[>..] = [];
    let ok2, why2 = compress::zlib_decompress(zz, b);
    if !ok2 || b != want { fail(str(name, ".zz: ", why2)); }

    var c: u8[>..] = [];
    let ok3, why3 = compress::inflate(raw, c);
    if !ok3 || c != want { fail(str(name, ".raw: ", why3)); }
}

fn check_bad(name: u8[:], expect: u8[:]) {
    let d = load(name);
    var out: u8[>..] = [];
    let ok, why = compress::gunzip(d, out);
    if ok { fail(str(name, ": the decoder accepted bad data")); }
    else if why != expect { fail(str(name, ": got \"", why, "\", want \"", expect, "\"")); }
}

fn main() {
    // Known values for the checksums.
    if compress::crc32("The quick brown fox jumps over the lazy dog") != 0x414fa339 { fail("crc32"); }
    if compress::adler32("Wikipedia") != 0x11e60398 { fail("adler32"); }
    if compress::crc32("") != 0 || compress::adler32("") != 1 { fail("empty checksums"); }

    check_case("empty");
    check_case("hello");
    var skipped = 0;
    for name in ["gen/stored", "gen/random", "gen/repeat", "gen/words", "gen/alice"] {
        if file_exists(str("data/", name, ".bin")) { check_case(name); } else { skipped++; }
    }

    let multi = load("multi.gz");
    var m: u8[>..] = [];
    let mok, mwhy = compress::gunzip(multi, m);
    if !mok || m != load("multi.bin") { fail(str("multi.gz: ", mwhy)); }

    check_bad("bad_crc.gz", "the CRC-32 does not match");
    check_bad("truncated.gz", "the compressed data ends too soon");
    check_bad("not_gzip.gz", "the data is not in gzip format");

    // The limit stops a decoder before the output gets too large.
    let bomb = load("bomb.gz");
    var small: u8[>..] = [];
    let lok, lwhy = compress::gunzip(bomb, small, 1000);
    if lok || small.len > 1000 { fail(str("limit: the decoder wrote ", small.len, " bytes")); }
    else if lwhy != "the output is larger than the limit" { fail(str("limit: ", lwhy)); }

    if skipped > 0 { print("compress: skipped ", skipped, " large cases. Run make_fixtures.py to make them."); }
    if failures == 0 { print("compress: all passed"); } else { print("compress: ", failures, " failed"); exit(1); }
}
