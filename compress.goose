// compress: decoders for DEFLATE (RFC 1951), zlib (RFC 1950) and gzip
// (RFC 1952). HTTP bodies and PNG images use these formats.
//
// The decoder writes the output into a builder that the caller owns. A
// back-reference reads the earlier output in that builder. Thus the decoder
// needs no separate window and no allocation.
//
// The design follows puff.c by Mark Adler, the zlib reference decoder. It
// decodes each Huffman code one bit at a time with canonical code tables.
//
//   import net.compress;
//
//   var text: u8[>..] = [];
//   let ok, why = compress::gunzip(data, text);
//   if !ok { print("cannot decode: ", why); }
//
// Each decoder has a `limit` parameter: the maximum count of output bytes.
// A small input can expand to a very large output ("a zip bomb"). The limit
// stops the decoder before that occurs.

namespace compress;

import std;

// ---------------------------------------------------------------- checksums

let CRC_TABLE: u32[256] = crc_table();

fn crc_table() -> u32[256] {
    var t: u32[256] = [0; 256];
    for n in 256 {
        var c = n as u32;
        for k in 8 { c = if (c & 1) != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 }; }
        t[n] = c;
    }
    return t;
}

// The CRC-32 of gzip and PNG. To continue a CRC over more data, give the
// previous result as `crc`.
fn crc32(data: const u8[:], crc: u32 = 0) -> u32 {
    var c = crc ^ 0xffffffff;
    for b in data { c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >> 8); }
    return c ^ 0xffffffff;
}

// The Adler-32 checksum of zlib. To continue a checksum over more data,
// give the previous result as `adler`.
fn adler32(data: const u8[:], adler: u32 = 1) -> u32 {
    var a: i64 = adler & 0xffff;
    var b: i64 = adler >> 16;
    var i = 0;
    while i < data.len {
        // 4096 bytes cannot make the sums overflow an i64 before the modulo.
        let end = min(i + 4096, data.len);
        for c in data[i..end] { a += c; b += a; }
        a %= 65521;
        b %= 65521;
        i = end;
    }
    return ((b << 16) | a) as u32;
}

// ---------------------------------------------------------------- Huffman codes

// A canonical Huffman code. count[n] is the count of codes with length n.
// symbol holds the symbols in code order.
struct Huffman { count: i32[16], symbol: i32[288] }

// Makes h from the code length of each symbol. Returns 0 for a complete
// code, a positive value for an incomplete code, and a negative value when
// the lengths make too many codes.
fn construct(h: Huffman&, lengths: const i32[:]) -> i64 {
    for i in 16 { h.count[i] = 0; }
    for l in lengths { h.count[l] += 1; }
    if h.count[0] == lengths.len { return 0; }

    var left: i64 = 1;
    for len in 1..16 {
        left <<= 1;
        left -= h.count[len];
        if left < 0 { return left; }
    }

    // offs[len] is where the first symbol with that length goes in symbol.
    var offs: i32[16] = [0; 16];
    for len in 1..15 { offs[len + 1] = offs[len] + h.count[len]; }
    for sym in lengths.len {
        let l = lengths[sym];
        if l != 0 {
            h.symbol[offs[l]] = sym as i32;
            offs[l] += 1;
        }
    }
    return left;
}

// The base value and the count of extra bits for each length symbol
// (257..285) and each distance symbol (0..29).
let LEN_BASE: i32[29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                         35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
let LEN_EXTRA: i32[29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                          3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
let DIST_BASE: i32[30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                          257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                          8193, 12289, 16385, 24577];
let DIST_EXTRA: i32[30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                           7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
// The sequence of the code length code lengths in a dynamic block header.
let CL_ORDER: i32[19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// ---------------------------------------------------------------- DEFLATE

// Decodes one raw DEFLATE stream at the start of `data` and appends the
// result to `out`. Returns the count of input bytes that the stream used,
// or -1 and the reason for the failure. Bytes after the stream are not part
// of the stream. The gzip and zlib trailers are there, for example.
fn inflate_raw(data: const u8[:], out: u8[>..]&, limit: i64 = 1 << 30) -> i64, const u8[:] {
    var pos = 0;           // the next input byte
    var bitbuf = 0;        // the input bits that the decoder did not use yet
    var bitcnt = 0;        // the count of those bits. It is always less than 8 between calls.
    let start = out.len;

    fn fail(why: const u8[:]) { return -1, why from inflate_raw; }

    // Returns the next n bits, the first bit in the least significant position.
    fn bits(n: i64) -> i64 {
        var v = bitbuf;
        while bitcnt < n {
            guard pos < data.len else { fail("the compressed data ends too soon"); }
            let b: i64 = data[pos];
            v |= b << bitcnt;
            pos++;
            bitcnt += 8;
        }
        bitbuf = v >> n;
        bitcnt -= n;
        return v & ((1 << n) - 1);
    }

    // Decodes one symbol with h. A Huffman code starts with its most
    // significant bit, so the decoder adds the bits one at a time.
    fn decode(h: const Huffman&) -> i64 {
        var code = 0;
        var first = 0;
        var index = 0;
        var buf = bitbuf;
        var left = bitcnt;
        for len in 1..16 {
            if left == 0 {
                guard pos < data.len else { fail("the compressed data ends too soon"); }
                buf = data[pos];
                pos++;
                left = 8;
            }
            code |= buf & 1;
            buf >>= 1;
            left--;
            let count: i64 = h.count[len];
            if code - count < first {
                bitbuf = buf;
                bitcnt = left;
                return h.symbol[index + (code - first)];
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        fail("a Huffman code is not valid");
        return -1;
    }

    // A stored block: a byte length, its complement, then the bytes.
    fn stored() {
        bitbuf = 0;
        bitcnt = 0;
        guard pos + 4 <= data.len else { fail("the compressed data ends too soon"); }
        let len: i64 = data[pos] | (data[pos + 1] as u16 << 8);
        let nlen: i64 = data[pos + 2] | (data[pos + 3] as u16 << 8);
        guard len == (nlen ^ 0xffff) else { fail("the length of a stored block does not match its complement"); }
        pos += 4;
        guard pos + len <= data.len else { fail("the compressed data ends too soon"); }
        guard out.len - start + len <= limit else { fail("the output is larger than the limit"); }
        out.append(data[pos..pos + len]);
        pos += len;
    }

    // Decodes literals and matches with the two codes, until the end-of-block symbol.
    fn codes(lencode: const Huffman&, distcode: const Huffman&) {
        loop {
            let sym = decode(lencode);
            if sym < 256 {
                guard out.len - start < limit else { fail("the output is larger than the limit"); }
                out.push(sym as! u8);
                continue;
            }
            if sym == 256 { return; }
            let ls = sym - 257;
            guard ls < 29 else { fail("a length symbol is not valid"); }
            let len = LEN_BASE[ls] + bits(LEN_EXTRA[ls]);
            let ds = decode(distcode);
            guard ds < 30 else { fail("a distance symbol is not valid"); }
            let dist = DIST_BASE[ds] + bits(DIST_EXTRA[ds]);
            guard dist <= out.len - start else { fail("a distance points before the start of the output"); }
            guard out.len - start + len <= limit else { fail("the output is larger than the limit"); }
            // A copy that does not overlap its own output is one append (a
            // memcpy). An overlapping copy repeats its bytes, so it goes one
            // byte at a time. The append made the decoder 23% faster.
            let from = out.len - dist;
            if dist >= len { out.append(out[from..from + len]); }
            else { for i in len { out.push(out[from + i]); } }
        }
    }

    var fixed_ready = false;
    var fixed_len = Huffman { .. };
    var fixed_dist = Huffman { .. };

    fn fixed() {
        if !fixed_ready {
            var lengths: i32[288] = [8; 288];
            for i in 144..256 { lengths[i] = 9; }
            for i in 256..280 { lengths[i] = 7; }
            construct(fixed_len, lengths);
            let dl: i32[30] = [5; 30];
            construct(fixed_dist, dl);
            fixed_ready = true;
        }
        codes(fixed_len, fixed_dist);
    }

    fn dynamic() {
        var lengths: i32[320] = [0; 320];
        let nlen = bits(5) + 257;
        let ndist = bits(5) + 1;
        let ncode = bits(4) + 4;
        guard nlen <= 286 && ndist <= 30 else { fail("a dynamic block header has too many codes"); }

        // First the code that encodes the code lengths.
        for i in ncode { lengths[CL_ORDER[i]] = bits(3) as i32; }
        var lencode = Huffman { .. };
        guard construct(lencode, lengths[..19]) == 0 else { fail("the code length code is not complete"); }

        // Then the code lengths of the literal/length code and the distance code.
        var index = 0;
        while index < nlen + ndist {
            let sym = decode(lencode);
            if sym < 16 {
                lengths[index] = sym as i32;
                index++;
                continue;
            }
            var len: i32 = 0;
            var rep = 0;
            if sym == 16 {
                guard index > 0 else { fail("a repeat code has no previous length"); }
                len = lengths[index - 1];
                rep = 3 + bits(2);
            } else if sym == 17 {
                rep = 3 + bits(3);
            } else {
                rep = 11 + bits(7);
            }
            guard index + rep <= nlen + ndist else { fail("a repeat code goes past the last length"); }
            for i in rep { lengths[index + i] = len; }
            index += rep;
        }
        guard lengths[256] != 0 else { fail("the block has no end-of-block code"); }

        // An incomplete code is valid only when it has exactly one code.
        let lerr = construct(lencode, lengths[..nlen]);
        guard lerr == 0 || (lerr > 0 && nlen - lencode.count[0] == 1) else {
            fail("the literal/length code is not valid");
        }
        var distcode = Huffman { .. };
        let derr = construct(distcode, lengths[nlen..nlen + ndist]);
        guard derr == 0 || (derr > 0 && ndist - distcode.count[0] == 1) else {
            fail("the distance code is not valid");
        }
        codes(lencode, distcode);
    }

    loop {
        let last = bits(1);
        let kind = bits(2);
        if kind == 0 { stored(); }
        else if kind == 1 { fixed(); }
        else if kind == 2 { dynamic(); }
        else { fail("a block has the type 3, which is not valid"); }
        if last == 1 { break; }
    }
    return pos, "";
}

// Decodes a raw DEFLATE stream and appends the result to `out`.
fn inflate(data: const u8[:], out: u8[>..]&, limit: i64 = 1 << 30) -> bool, const u8[:] {
    let used, why = inflate_raw(data, out, limit);
    return used >= 0, why;
}

// ---------------------------------------------------------------- zlib

// True if the first two bytes of `d` are a valid zlib header.
fn is_zlib(d: const u8[:]) -> bool {
    guard d.len >= 2 else { return false; }
    let cmf: i64 = d[0];
    let flg: i64 = d[1];
    return (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && (cmf * 256 + flg) % 31 == 0;
}

// Decodes zlib data and appends the result to `out`. The function checks
// the Adler-32 checksum at the end.
fn zlib_decompress(data: const u8[:], out: u8[>..]&, limit: i64 = 1 << 30) -> bool, const u8[:] {
    guard is_zlib(data) else { return false, "the data is not in zlib format"; }
    guard (data[1] & 0x20) == 0 else { return false, "zlib preset dictionaries are not supported"; }
    let before = out.len;
    let used, why = inflate_raw(data[2..], out, limit);
    guard used >= 0 else { return false, why; }
    let t = 2 + used;
    guard t + 4 <= data.len else { return false, "the zlib checksum is missing"; }
    let want: u32 = (data[t] as u32 << 24) | (data[t + 1] as u32 << 16) | (data[t + 2] as u32 << 8) | data[t + 3];
    guard adler32(out[before..]) == want else { return false, "the Adler-32 checksum does not match"; }
    return true, "";
}

// ---------------------------------------------------------------- gzip

fn le32(d: const u8[:], i: i64) -> u32 {
    d[i] | (d[i + 1] as u32 << 8) | (d[i + 2] as u32 << 16) | (d[i + 3] as u32 << 24)
}

// Decodes gzip data and appends the result to `out`. A gzip file can
// contain more than one member. The function decodes all the members and
// checks the CRC-32 and the size of each member. It ignores bytes after
// the last member that are not the start of a new member.
fn gunzip(data: const u8[:], out: u8[>..]&, limit: i64 = 1 << 30) -> bool, const u8[:] {
    let start = out.len;
    var p = 0;
    var members = 0;
    while p < data.len {
        let m = data[p..];
        guard m.len >= 18 && m[0] == 31 && m[1] == 139 else {
            if members > 0 { break; }
            return false, "the data is not in gzip format";
        }
        guard m[2] == 8 else { return false, "the gzip compression method is not DEFLATE"; }
        let flg = m[3];
        var h = 10;
        // The optional header fields: FEXTRA, FNAME, FCOMMENT and FHCRC.
        if (flg & 4) != 0 {
            guard h + 2 <= m.len else { return false, "the gzip header ends too soon"; }
            let xlen: i64 = m[h] | (m[h + 1] as u16 << 8);
            h += 2 + xlen;
        }
        if (flg & 8) != 0 { while h < m.len && m[h] != 0 { h++; } h++; }
        if (flg & 16) != 0 { while h < m.len && m[h] != 0 { h++; } h++; }
        if (flg & 2) != 0 { h += 2; }
        guard h <= m.len else { return false, "the gzip header ends too soon"; }

        let before = out.len;
        let used, why = inflate_raw(m[h..], out, limit - (before - start));
        guard used >= 0 else { return false, why; }
        let t = h + used;
        guard t + 8 <= m.len else { return false, "the gzip trailer is missing"; }
        guard crc32(out[before..]) == le32(m, t) else { return false, "the CRC-32 does not match"; }
        guard ((out.len - before) & 0xffffffff) == le32(m, t + 4) else {
            return false, "the size in the gzip trailer does not match";
        }
        p += t + 8;
        members++;
    }
    return true, "";
}
