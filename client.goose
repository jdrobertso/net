// A client that does not block: requests run on worker threads, and the
// calling thread continues its work. Use it, for example, in the frame
// loop of a program with a window.
//
//   import net.client;
//
//   var c = http::client();                       // 4 workers
//   let page = http::submit(c, "GET", "https://example.com/");
//   loop {
//       let id, r = http::poll(c);                 // never waits
//       if id == page { print(r.status, " ", http::body(r).len, " bytes"); break; }
//       draw_frame();
//   }
//   http::close(c);
//
// Each worker is a thread_fn with a Session of its own, so a worker keeps
// its connections open between jobs. The client keeps one cookie jar. Each
// job takes a copy of the jar, and the worker sends back only the changes.
// Thus two requests at the same time cannot lose the cookies of each other.
//
// Threads need `goose build`. The run in the process of the compiler
// (`goose file.goose`) cannot start them. The blocking functions in
// http.goose work in the two forms.
//
// A program can have only one Client at a time, because all the workers
// share the same queues: one queue for each message type.

namespace http;

import std;
import cookie;          // the cookie.goose of this package

// The messages on the queues. All of them are flat, as a queue needs.
struct Job {
    id: i64,
    quit: bool,             // a message that stops one worker
    progress: bool,         // send Progress messages for this job
    method: u8[..16],
    opts: Options,
    target: u8[],
    headers: u8[],
    body: u8[],
    cookies: u8[],          // the jar of the client when the job started
}

struct Done {
    id: i64,
    status: i64,
    redirects: i64,
    url_end: i64,
    head_end: i64,
    data: u8[],             // as in Response
    delta: u8[],            // the cookie changes (see cookie::diff)
}

// How much of the body of a job arrived. `total` is the Content-Length, or
// -1 when the response has none.
struct Progress { id: i64, got: i64, total: i64 }

let MAX_WORKERS = 64;
let PROGRESS_STEP = 65536;     // a worker sends Progress after each 64 KB

struct Client {
    opts: Options,
    workers: i64[..64],     // the thread ids
    next_id: i64,
    in_flight: i64,
    cookies: u8[>..],       // the cookie jar (see cookie.goose)
}

var clients_open = 0;

// Starts a client with `workers` threads. The workers use `opts` for each
// request, and so does the client for its cookies.
fn client(opts: Options = Options { .. }, workers: i64 = 4) -> Client {
    guard clients_open == 0 else { abort("http::client: a program can have only one Client at a time"); }
    guard workers >= 1 && workers <= MAX_WORKERS else { abort("http::client: the count of workers must be 1 to 64"); }
    clients_open++;
    var c = Client { opts: opts, workers: [], next_id: 1, in_flight: 0, cookies: [] };
    for i in workers { c.workers.push(thread_spawn(worker)); }
    return c;
}

// Starts a request and returns its id at once. With `progress`, the
// worker sends Progress messages while the body arrives. A request with
// progress asks for no compression, as stream does.
fn submit(c: Client&, method: const u8[:], target: const u8[:], headers: const u8[:] = "",
          body: const u8[:] = "", progress: bool = false) -> i64 {
    let id = c.next_id;
    c.next_id++;
    var m: u8[..16] = [];
    m.append(method[..min(method.len, 16)]);
    qput(Job {
        id: id, quit: false, progress: progress, method: m, opts: c.opts,
        target: target, headers: headers, body: body, cookies: c.cookies[..],
    });
    c.in_flight++;
    return id;
}

// The count of requests that are not complete yet.
fn pending(c: const Client&) -> i64 { c.in_flight }

fn take(c: Client&, d: const Done&) -> Response {
    c.in_flight--;
    cookie::apply(c.cookies, d.delta);
    return Response { status: d.status, redirects: d.redirects, url_end: d.url_end, head_end: d.head_end, data: d.data[..] };
}

// Returns the id and the Response of a request that is complete, if there
// is one. Else it returns -1 and an empty Response. It never waits.
fn poll(c: Client&) -> i64, Response {
    let d, got = qpoll<Done>();
    guard got else { return -1, Response { .. }; }
    return d.id, take(c, d);
}

// Waits for the next request that completes, for a maximum of `timeout_ms`.
// A negative value means no time limit. Returns -1 and an empty Response
// when the time limit expires, or at once when no request is in flight.
fn next(c: Client&, timeout_ms: i64 = -1) -> i64, Response {
    guard c.in_flight > 0 else { return -1, Response { .. }; }
    if timeout_ms < 0 {
        let d = qget<Done>();
        return d.id, take(c, d);
    }
    let d, got = qget<Done>(timeout_ms);
    guard got else { return -1, Response { .. }; }
    return d.id, take(c, d);
}

// Returns the next Progress message, if there is one. It never waits.
fn progress(c: const Client&) -> Progress, bool {
    let p, got = qpoll<Progress>();
    return p, got;
}

// Stops the workers and waits for them. The workers first complete the
// jobs in the queue. Their responses stay in the queue, so call next or
// poll before close to get them.
fn close(c: Client&) {
    for w in c.workers {
        qput(Job { id: 0, quit: true, progress: false, method: [], opts: c.opts,
                   target: [], headers: [], body: [], cookies: [] });
    }
    for w in c.workers { thread_wait(w); }
    c.workers.clear();
    clients_open--;
}

fn load_cookies(c: Client&, path: const u8[:]) -> bool {
    var text: u8[>..] = [];
    guard read_file(path, text) else { return false; }
    c.cookies.clear();
    c.cookies.append(text);
    return true;
}

fn save_cookies(c: const Client&, path: const u8[:]) -> bool {
    var text: u8[>..] = [];
    cookie::persistent(text, c.cookies, now_s());
    return write_file_atomic(path, text);
}

// ---------------------------------------------------------------- the workers

thread_fn worker() {
    var s = session();
    loop {
        let job = qget<Job>();
        if job.quit { break; }
        s.opts = job.opts;
        s.cookies.clear();
        s.cookies.append(job.cookies);
        run_job(s, job);
    }
    close(s);
}

fn run_job(s: Session&, job: const Job&) {
    var delta: u8[>..] = [];
    if !job.progress {
        let r = request(s, job.method, job.target, job.headers, job.body);
        cookie::diff(delta, job.cookies, s.cookies);
        qput(Done { id: job.id, status: r.status, redirects: r.redirects, url_end: r.url_end,
                    head_end: r.head_end, data: r.data[..], delta: delta[..] });
        return;
    }

    var got: u8[>..] = [];
    var sent = 0;
    let r = stream(s, job.method, job.target, job.headers, job.body) { chunk, total =>
        got.append(chunk);
        if got.len - sent >= PROGRESS_STEP || (total >= 0 && got.len == total) {
            qput(Progress { id: job.id, got: got.len, total: total });
            sent = got.len;
        }
    };
    cookie::diff(delta, job.cookies, s.cookies);
    guard ok(r) else {
        qput(Done { id: job.id, status: 0, redirects: 0, url_end: r.url_end, head_end: r.head_end,
                    data: r.data[..], delta: delta[..] });
        return;
    }
    // A server can compress the body although the request asked for no compression.
    var decoded: u8[>..] = [];
    let ce, has_ce = header(r, "content-encoding");
    if job.opts.decompress && has_ce && got.len > 0 && !url::equal_ci(ce, "identity") {
        let dok, why = decode_body(ce, got, decoded, job.opts.max_bytes);
        if !dok {
            let f = failure(final_url(r), str("cannot decode the ", ce, " body: ", why));
            qput(Done { id: job.id, status: 0, redirects: 0, url_end: f.url_end, head_end: f.head_end,
                        data: f.data[..], delta: delta[..] });
            return;
        }
    }
    let content = if decoded.len > 0 { decoded[..] } else { got[..] };
    qput(Done { id: job.id, status: r.status, redirects: r.redirects, url_end: r.url_end,
                head_end: r.head_end, data: concat3(final_url(r), head(r), content), delta: delta[..] });
}
