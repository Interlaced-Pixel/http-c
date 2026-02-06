# HTTP/1.0 Full Implementation Plan (RFC 1945)

## Current State Assessment

### What's Already Working
- Streaming callback-based HTTP parser (request line, headers, body)
- GET and POST methods with body buffering and spill-to-disk
- `Content-Length` and `Connection` header handling
- MIME type detection from file extension
- Static file serving and directory listing
- URL decoding, path normalization, directory traversal protection
- Non-blocking I/O with `select()`, connection timeout
- Keep-alive support, chunked transfer encoding (response)
- SIGPIPE handling, SO_REUSEADDR/SO_REUSEPORT
- Memory pool allocator
- Platform abstraction (POSIX/Windows)

### What's Missing (per RFC 1945)
The implementation is missing proper status code handling, most standard response headers, the HEAD method, conditional GET, error body generation, HTTP/0.9 compatibility, and Basic authentication. Each gap is addressed below as a discrete, testable step.

---

## Phase 1: Response Infrastructure

The response path currently hardcodes `"HTTP/1.0 %d OK"` for every status code and omits standard headers (Date, Server, etc.). Every subsequent feature depends on a correct response builder.

### Step 1: Status Code Reason Phrase Registry

**Goal:** Map every RFC 1945 status code to its reason phrase so responses read `HTTP/1.0 404 Not Found` instead of `HTTP/1.0 404 OK`.

**RFC Reference:** Section 6.1.1

**Implementation:**
1. Add a function `const char *http_status_reason(int status)` in `http.h` (declaration before `#ifdef HTTP_IMPLEMENTATION`, definition inside it).
2. Implement with a `switch` covering all RFC 1945 codes:
   - `200` → `"OK"`
   - `201` → `"Created"`
   - `202` → `"Accepted"`
   - `204` → `"No Content"`
   - `301` → `"Moved Permanently"`
   - `302` → `"Moved Temporarily"`
   - `304` → `"Not Modified"`
   - `400` → `"Bad Request"`
   - `401` → `"Unauthorized"`
   - `403` → `"Forbidden"`
   - `404` → `"Not Found"`
   - `500` → `"Internal Server Error"`
   - `501` → `"Not Implemented"`
   - `502` → `"Bad Gateway"`
   - `503` → `"Service Unavailable"`
   - Default: derive generic class text from first digit (e.g., 4xx → `"Client Error"`)
3. Replace every `snprintf(... "%d OK" ...)` in `http_conn_send_response`, `http_conn_send_file`, and `http_conn_start_chunked_response` with `"%d %s", status, http_status_reason(status)`.

**Test:** Unit test that calls `http_status_reason()` for each defined code and the default path. Verify via `curl -v` that responses show correct phrases.

**Files Changed:** `http.h`  
**New Test File:** `tests/test_status.cpp` (or add cases to `test_utils.cpp`)

---

### Step 2: HTTP Date Formatting (RFC 1123)

**Goal:** Generate dates in the RFC 1123 format required by the `Date`, `Last-Modified`, and `Expires` headers.

**RFC Reference:** Section 3.3 — `Sun, 06 Nov 1994 08:49:37 GMT`

**Implementation:**
1. Add `int http_format_date(char *buf, size_t buf_size, time_t t)` — writes the RFC 1123 date string into `buf`.
2. Use `gmtime()` + `strftime()` with format `"%a, %d %b %Y %H:%M:%S GMT"`.
3. Also add `time_t http_parse_date(const char *str)` for parsing all three RFC-allowed formats (RFC 1123, RFC 850, asctime). This is needed for `If-Modified-Since` in Step 8.
   - Try `strptime` with `"%a, %d %b %Y %H:%M:%S GMT"` first (RFC 1123).
   - Fall back to `"%A, %d-%b-%y %H:%M:%S GMT"` (RFC 850).
   - Fall back to `"%a %b %d %H:%M:%S %Y"` (asctime).
   - Return `(time_t)-1` on failure.

**Test:** Format a known `time_t`, check string. Parse all three formats, check round-trip.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_utils.cpp`

---

### Step 3: Unified Response Header Builder

**Goal:** Every HTTP response must include `Date`, `Server`, `Content-Type`, `Content-Length` (when known), and `Connection`. Centralize this into a helper so all response paths are consistent.

**RFC Reference:** Sections 10.6 (Date), 10.14 (Server), 10.4 (Content-Length), 10.5 (Content-Type)

**Implementation:**
1. Add a new internal helper:
   ```c
   static int http_build_response_headers(
       char *buf, size_t buf_size,
       int status,
       const char *content_type,
       size_t content_length,    /* (size_t)-1 if unknown / chunked */
       int keep_alive,
       const char *extra_headers /* NULL or additional "Key: Value\r\n" pairs */
   );
   ```
2. This function writes:
   ```
   HTTP/1.0 <status> <reason>\r\n
   Date: <RFC 1123 date>\r\n
   Server: HTTP-C/1.0\r\n
   Content-Type: <content_type>\r\n
   Content-Length: <content_length>\r\n    (omitted if (size_t)-1)
   Connection: keep-alive | close\r\n
   <extra_headers>                         (if non-NULL)
   \r\n
   ```
3. Refactor `http_conn_send_response`, `http_conn_send_file`, `http_conn_send_directory_listing`, and `http_conn_start_chunked_response` to call this helper instead of inline `snprintf`.
4. Define a configurable `HTTP_SERVER_NAME` macro defaulting to `"HTTP-C/1.0"`.

**Test:** Integration test — `curl -I http://localhost:PORT/` and verify `Date:` and `Server:` headers are present and correctly formatted.

**Files Changed:** `http.h`

---

## Phase 2: Core Methods

### Step 4: HEAD Method

**Goal:** HEAD is identical to GET except no entity body is sent. The response headers (including `Content-Length`) must be the same as if it were a GET.

**RFC Reference:** Section 8.2

**Implementation:**
1. The parser already recognizes `HTTP_METHOD_HEAD`. No parser changes needed.
2. In `http_conn_send_file`, add a `is_head` check:
   - Compute headers exactly as for GET (including `Content-Length` from the file size).
   - Send headers only; skip `socket_send_all(conn->sock, content.data, content.size)`.
3. In `http_conn_send_response`, do the same: compute `Content-Length` from `body`, but don't send the body bytes if method is HEAD.
4. Store `conn->method` so response functions can check it. (Already stored — ✓)
5. Update `example.c`'s `request_handler` to route HEAD requests through the same path as GET (it currently doesn't check for HEAD explicitly, but since the response functions will handle it, no routing change may be needed — verify).

**Test:**
```bash
curl -I http://localhost:8080/index.html
# Should return headers with Content-Length matching the file size, but empty body.
```
Unit test: send HEAD request over socketpair, verify response has headers but zero body bytes after `\r\n\r\n`.

**Files Changed:** `http.h`, possibly `example.c`  
**New Test Cases:** `tests/test_server.cpp`

---

### Step 5: Proper POST/PUT/DELETE Handling and 501 for Unknown Methods

**Goal:** Return correct status codes for POST (200/201/204), handle PUT and DELETE as per Appendix D, and return `501 Not Implemented` for truly unknown methods.

**RFC Reference:** Sections 8.1-8.3, Appendix D.1.1-D.1.2, Section 9.4 (501)

**Implementation:**
1. **501 Not Implemented:** In `example.c`'s request handler (and document as a pattern), check `method == HTTP_METHOD_UNKNOWN` and respond with `501`.
2. **405 Method Not Allowed (optional, not in RFC 1945 but good practice):** For methods that are recognized but not supported on a particular resource, return `501` (the HTTP/1.0 equivalent). Include an `Allow` header listing valid methods.
3. **POST response codes:** The example handler currently doesn't do anything meaningful with POST. Add a pattern showing:
   - `201 Created` with `Location` header when a resource is created.
   - `200 OK` with a body describing the result.
   - `204 No Content` when no body is returned.
4. **PUT:** In example handler, implement a simple file-write handler:
   - Validate path safety with `path_is_safe()`.
   - Write `conn->body_buf` / upload file to the target path.
   - Return `201 Created` if new file, `200 OK` if overwritten.
5. **DELETE:** In example handler:
   - Validate path safety.
   - `unlink()` the file.
   - Return `200 OK` with confirmation body, or `404` if file doesn't exist.
6. **Content-Length validation on POST/PUT:** If `Content-Length` is missing from a POST/PUT, respond with `400 Bad Request`. Implement this check in `on_headers_complete` or at request dispatch time.

**Test:** `curl -X PUT -d "hello" http://localhost:8080/test.txt`, verify file created, then `curl -X DELETE http://localhost:8080/test.txt`, verify file removed. Send `curl -X FOOBAR ...`, verify 501.

**Files Changed:** `http.h`, `example.c`  
**New Test Cases:** `tests/test_server.cpp`

---

## Phase 3: Conditional Requests & Caching

### Step 6: Last-Modified Header on File Responses

**Goal:** Include `Last-Modified` in every response that serves a file from disk.

**RFC Reference:** Section 10.10

**Implementation:**
1. In `http_conn_send_file`, after `file_read`, call `stat()` on the file to get `st.st_mtime`.
2. Format with `http_format_date()` (from Step 2).
3. Pass as an extra header string to `http_build_response_headers` (from Step 3).
4. Similarly update `http_conn_send_directory_listing` to include `Last-Modified` as the most recent `st_mtime` among listed entries (or current time).

**Test:** `curl -v http://localhost:8080/index.html`, verify `Last-Modified:` header is present and matches the file's actual mtime.

**Files Changed:** `http.h`

---

### Step 7: Expires Header Support

**Goal:** Allow the server to send `Expires` headers for cache control.

**RFC Reference:** Section 10.7

**Implementation:**
1. Add a configurable `DEFAULT_EXPIRES_SEC` macro (default 0, meaning no Expires header sent).
2. If `DEFAULT_EXPIRES_SEC > 0`, compute `time(NULL) + DEFAULT_EXPIRES_SEC`, format with `http_format_date()`, and include as an extra header in file responses.
3. Optionally allow per-MIME-type expiry configuration (e.g., images expire in 1 hour, HTML in 0 seconds). This can be a simple hardcoded table or a callback.

**Test:** Set `DEFAULT_EXPIRES_SEC` to 3600, verify `Expires:` header is present and is ~1 hour in the future.

**Files Changed:** `http.h`

---

### Step 8: Conditional GET — If-Modified-Since / 304 Not Modified

**Goal:** Support the conditional GET optimization: if a client sends `If-Modified-Since` and the file hasn't changed, return `304 Not Modified` with no body.

**RFC Reference:** Sections 8.1, 10.9, 9.3 (304 status)

**Implementation:**
1. In `on_header`, detect `If-Modified-Since` and store the raw value in a new field on `http_conn_t`:
   ```c
   time_t if_modified_since;   /* 0 if not present */
   ```
2. In `on_headers_complete`, parse the stored value using `http_parse_date()` (from Step 2) and store the result.
3. In `http_conn_send_file` (and any GET handler path), before reading file contents:
   - `stat()` the file to get `st.st_mtime`.
   - If `conn->if_modified_since > 0` and `st.st_mtime <= conn->if_modified_since`, send a `304 Not Modified` response with only `Date`, `Server`, and optionally `Expires` headers — **no body, no Content-Length**.
   - Otherwise proceed normally.
4. Per RFC: If `If-Modified-Since` date is in the future (later than server's current time), treat it as invalid and serve normally.
5. HEAD requests with `If-Modified-Since` should be ignored per Section 8.2.
6. Reset `conn->if_modified_since = 0` during connection reset / parser reset.

**Test:**
```bash
# First request — get Last-Modified
curl -v http://localhost:8080/index.html
# Second request with If-Modified-Since — should get 304
curl -v -H "If-Modified-Since: <value from above>" http://localhost:8080/index.html
# Modify the file, repeat — should get 200
```

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_parser.cpp`, `tests/test_server.cpp`

---

## Phase 4: Redirects & Error Responses

### Step 9: Redirect Support (301, 302)

**Goal:** Provide API functions for sending redirect responses with a `Location` header.

**RFC Reference:** Sections 9.3 (301, 302), 10.11 (Location)

**Implementation:**
1. Add `int http_conn_send_redirect(http_conn_t *conn, int status, const char *location)`:
   - `status` must be 301 or 302.
   - Build response with `Location: <url>\r\n` as extra header.
   - Body: a short HTML page with a hyperlink to the new location (per RFC: "should contain a short note with a hyperlink to the new URL").
   ```html
   <html><body><p>Moved to <a href="URL">URL</a></p></body></html>
   ```
2. Use in `example.c`: when a directory path is requested without a trailing `/`, redirect to `path/` (common webserver behavior).

**Test:** `curl -v http://localhost:8080/somedir` (without trailing slash) → expect 301 with `Location: /somedir/`.

**Files Changed:** `http.h`, `example.c`  
**New Test Cases:** `tests/test_server.cpp`

---

### Step 10: Proper Error Response Bodies

**Goal:** Error responses (400, 403, 404, 500, 501, 503) should include an HTML entity body explaining the error, per RFC 1945 Section 9.4/9.5.

**RFC Reference:** Sections 9.4, 9.5 — "the server should include an entity containing an explanation of the error situation"

**Implementation:**
1. Add `int http_conn_send_error(http_conn_t *conn, int status, const char *detail)`:
   - Generates an HTML body:
     ```html
     <html><head><title>STATUS REASON</title></head>
     <body><h1>STATUS REASON</h1><p>DETAIL</p></body></html>
     ```
   - Sets `Content-Type: text/html`.
   - Calls `http_build_response_headers` + sends.
2. Replace all `http_conn_send_response(conn, 404, "Not found or access denied")` and similar plain-text error calls with `http_conn_send_error()`.
3. For HEAD requests, send the headers but omit the body (reuse Step 4 logic).

**Test:** `curl http://localhost:8080/nonexistent` → verify HTML error page with 404 status.

**Files Changed:** `http.h`, `example.c`

---

## Phase 5: Authentication

### Step 11: Basic Authentication (RFC 1945 Section 11.1)

**Goal:** Support HTTP Basic Authentication with a challenge/response mechanism.

**RFC Reference:** Section 11, 11.1, 10.2 (Authorization), 10.16 (WWW-Authenticate)

**Implementation:**
1. Add configuration macros:
   ```c
   #ifndef ENABLE_AUTH
   #define ENABLE_AUTH 0
   #endif
   #ifndef AUTH_REALM
   #define AUTH_REALM "Restricted"
   #endif
   ```
2. Add a callback type for credential validation:
   ```c
   typedef int (*http_auth_cb)(const char *username, const char *password, void *user_data);
   ```
3. Add `http_server_set_auth_handler(http_server_t *server, http_auth_cb cb, void *user_data)`.
4. Add a Base64 decoder function (minimal, ~30 lines):
   ```c
   static int base64_decode(const char *in, size_t in_len, char *out, size_t out_size);
   ```
5. In the request dispatch path (before calling `on_request`):
   - If auth is enabled and no `Authorization` header is present, send:
     ```
     HTTP/1.0 401 Unauthorized\r\n
     WWW-Authenticate: Basic realm="REALM"\r\n
     ...
     ```
   - If `Authorization: Basic <base64>` is present, decode, split on `:`, call the auth callback.
   - If callback returns 0 (failure), send `403 Forbidden`.
6. Parse the `Authorization` header in `on_header`:
   - Store the raw value in `http_conn_t` (add `char auth_header[MAX_HEADER_VALUE_LEN]`).

**Test:**
```bash
# No credentials → 401
curl -v http://localhost:8080/secret
# With credentials → 200
curl -u admin:password http://localhost:8080/secret
```

**Files Changed:** `http.h`, `example.c`  
**New Test Cases:** `tests/test_auth.cpp`

---

## Phase 6: Protocol Compliance Hardening

### Step 12: HTTP/0.9 Simple-Request Compatibility

**Goal:** Per RFC 1945 Section 4.1, servers must recognize `Simple-Request = "GET" SP Request-URI CRLF` (no version string) and respond with a `Simple-Response` (body only, no headers).

**RFC Reference:** Sections 4.1, 5

**Implementation:**
1. Modify request line parser: if after tokenizing the request line, `version` is NULL (only method + URI present), treat it as HTTP/0.9.
2. Add a flag `int http09` to `http_conn_t`.
3. When `http09` is set:
   - Only accept GET method.
   - Response is a Simple-Response: send entity body directly, no status line, no headers.
   - Close connection after sending (no keep-alive).
4. Reject non-GET Simple-Requests by closing the connection.

**Test:** `printf "GET /index.html\r\n" | nc localhost 8080` → should receive raw HTML with no headers.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_parser.cpp`

---

### Step 13: Pragma: no-cache Handling

**Goal:** When a request includes `Pragma: no-cache`, the server should not serve from any internal cache (relevant if caching is later added).

**RFC Reference:** Section 10.12

**Implementation:**
1. In `on_header`, detect `Pragma` header and check for `no-cache` directive.
2. Store a flag `int no_cache` on `http_conn_t`.
3. Currently the server has no cache, so this is a parsing/storage step for forward compatibility. If `Expires` headers are being set (Step 7), a `Pragma: no-cache` request could suppress the `Expires` header in the response or set `Expires` to the current date.

**Test:** Unit test that verifies the `no_cache` flag is set after parsing a request with `Pragma: no-cache`.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_parser.cpp`

---

### Step 14: Request Header Logging (User-Agent, Referer, From)

**Goal:** Parse and log the informational request headers defined in RFC 1945.

**RFC Reference:** Sections 10.15 (User-Agent), 10.13 (Referer), 10.8 (From)

**Implementation:**
1. These headers are already being captured generically in `conn->headers[]`. No new parsing is needed.
2. Add access-log style output when a request completes:
   ```
   INF: 200 GET /index.html "Mozilla/5.0" "http://example.com/page" 1234ms
   ```
3. Add a helper to find a header value by name:
   ```c
   const char *http_conn_get_header(const http_conn_t *conn, const char *field);
   ```
   This iterates `conn->headers[]` doing `strcasecmp` and returns the value or NULL.
4. Call it from the request dispatch path to extract `User-Agent`, `Referer`, and `From` for logging.

**Test:** `curl -A "TestAgent/1.0" http://localhost:8080/` → verify log line includes "TestAgent/1.0".

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_server.cpp`

---

### Step 15: Allow Header

**Goal:** Include an `Allow` header in responses where appropriate (e.g., in `501` and `405`-style responses).

**RFC Reference:** Section 10.1

**Implementation:**
1. In `http_conn_send_error`, when status is `501`, include `Allow: GET, HEAD, POST\r\n` (or the actual set of methods the server supports).
2. Add the `Allow` header to any `OPTIONS` response (if you choose to support it; it's not in RFC 1945 core but the method is already parsed).
3. For `OPTIONS *`, respond with `200 OK` and `Allow: GET, HEAD, POST, PUT, DELETE`.

**Test:** `curl -X OPTIONS http://localhost:8080/` → verify `Allow:` header.

**Files Changed:** `http.h`, `example.c`

---

### Step 16: Content-Length Validation for POST/PUT

**Goal:** Per RFC 1945, all POST requests with a body MUST include a valid `Content-Length`. If missing, respond with `400 Bad Request`.

**RFC Reference:** Sections 7.2.2, 8.3

**Implementation:**
1. In `on_headers_complete`, after processing all headers:
   - If method is POST or PUT and `expected_content_length == 0` and no `Content-Length` header was seen, set a flag `int bad_request` on `http_conn_t`.
2. In `on_complete` (or right before dispatching `on_request`), if `bad_request` is set, send `400 Bad Request` and skip the handler.
3. Also validate: if `Content-Length` is present but not a valid non-negative integer, set `bad_request`.

**Test:** `curl -X POST http://localhost:8080/api -d "" --no-buffer` without Content-Length → 400. With Content-Length → 200.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_parser.cpp`

---

## Phase 7: Extended Content Handling

### Step 17: Content-Encoding Support (gzip)

**Goal:** Support `Content-Encoding: x-gzip` / `gzip` for file responses when the client sends `Accept-Encoding: gzip`.

**RFC Reference:** Sections 3.5, 10.3, Appendix D.2.3

**Implementation:**
1. This is optional for an embedded server and adds a zlib dependency. Gate behind `ENABLE_GZIP` macro (default 0).
2. If enabled:
   - Parse `Accept-Encoding` header in `on_header`, check for `gzip` or `x-gzip`. Store flag `int accept_gzip` on `http_conn_t`.
   - In `http_conn_send_file`, if file size > some threshold (e.g., 1KB) and content is a compressible type (text/*, application/json, application/javascript, etc.) and `accept_gzip`:
     - Compress file contents with `deflate()` (zlib).
     - Add `Content-Encoding: gzip\r\n` to response.
     - Set `Content-Length` to the compressed size.
   - For chunked responses, compress each chunk (more complex, defer if needed).
3. Link with `-lz`.

**Test:**
```bash
curl -v -H "Accept-Encoding: gzip" http://localhost:8080/index.html | gunzip
```

**Files Changed:** `http.h`, `Makefile`  
**New Test Cases:** `tests/test_server.cpp`

---

### Step 18: Additional MIME Types

**Goal:** Expand the MIME type registry to cover common modern file types.

**RFC Reference:** Section 3.6, 10.5

**Implementation:**
1. Add to `mime_type_from_path`:
   - `.woff` / `.woff2` → `font/woff` / `font/woff2`
   - `.ttf` → `font/ttf`
   - `.otf` → `font/otf`
   - `.mp4` → `video/mp4`
   - `.webm` → `video/webm`
   - `.mp3` → `audio/mpeg`
   - `.wav` → `audio/wav`
   - `.webp` → `image/webp`
   - `.avif` → `image/avif`
   - `.pdf` → `application/pdf`
   - `.zip` → `application/zip`
   - `.tar` → `application/x-tar`
   - `.gz` → `application/gzip`
   - `.wasm` → `application/wasm`
   - `.csv` → `text/csv`
   - `.md` → `text/markdown`
   - `.yaml` / `.yml` → `text/yaml`
2. Consider making the comparison case-insensitive (e.g., `.JPG` → `image/jpeg`).

**Test:** Add test cases to `test_utils.cpp` for each new MIME type.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_utils.cpp`

---

## Phase 8: Robustness & Security

### Step 19: Malformed Request Handling

**Goal:** Gracefully handle malformed requests — incomplete lines, missing method/URI/version, oversized headers, binary garbage.

**RFC Reference:** Appendix B (Tolerant Applications), Section 9.4 (400 Bad Request)

**Implementation:**
1. **Oversized request line:** Parser already checks `MAX_REQUEST_LINE_LEN`. When exceeded, the parser returns early. Add explicit `400 Bad Request` response and close the connection.
2. **Oversized header lines:** Same pattern — respond 400 and close.
3. **Missing/invalid components:** In the request line parser, if `method_str`, `uri`, or `version` is NULL after tokenizing, respond 400. Currently the parser just returns `i` (stops parsing), but the connection hangs. Instead, trigger an error callback or set an error flag.
4. **Binary/non-ASCII in request line:** Add validation that method, URI, and version contain only valid characters (printable ASCII, per the `token` and `URI` rules).
5. **LF-only line termination:** Per Appendix B, be tolerant — recognize bare LF as a line terminator. The current parser already handles this partially (it skips `\n` in request line and header states). Verify edge cases.
6. Add a `http_parser_error_t` enum and `int error` field to `http_parser_t` so the server loop can detect parse failures and send appropriate responses.

**Test:**
- Send `"GARBAGE\r\n\r\n"` → 400.
- Send a 5000-byte request line → 400.
- Send a header line exceeding `MAX_HEADER_LINE_LEN` → 400.
- Send `"GET /foo\r\n\r\n"` (no version, but not a valid Simple-Request either) → 400.

**Files Changed:** `http.h`  
**New Test Cases:** `tests/test_parser.cpp`

---

### Step 20: Rate Limiting

**Goal:** Prevent abuse by limiting requests per connection and connections per IP.

**RFC Reference:** Not in RFC 1945 directly, but Section 12 (Security Considerations)

**Implementation:**
1. Add a per-connection request counter. After `MAX_REQUESTS_PER_CONNECTION` (default 100), close the connection.
2. Add a simple IP tracking structure:
   ```c
   typedef struct {
       uint32_t ip;
       unsigned long first_seen;
       int conn_count;
   } ip_tracker_t;
   ```
3. Maintain a small array (e.g., 64 entries) of `ip_tracker_t`. On each new connection, check if the IP has exceeded `MAX_CONNECTIONS_PER_IP` (default 4) within a time window.
4. If exceeded, respond `503 Service Unavailable` and close immediately.

**Test:** Open MAX_CONNECTIONS_PER_IP + 1 connections from the same IP, verify the last one gets rejected.

**Files Changed:** `http.h`

---

### Step 21: Request Timeout and Slowloris Protection

**Goal:** Close connections that send data too slowly (Slowloris attack mitigation).

**RFC Reference:** Section 12 (Security Considerations)

**Implementation:**
1. The existing `CONNECTION_TIMEOUT_SEC` (10s idle timeout) already provides some protection.
2. Add a `HEADER_TIMEOUT_SEC` (default 5s): if the parser hasn't reached `HTTP_PARSER_DONE` state within this time after the first byte, close the connection.
3. Track `unsigned long first_byte_time` on `http_conn_t`. Set it when the first `recv()` succeeds. Check it in the timeout sweep.
4. Add `MAX_REQUEST_SIZE` (default 8192): if total bytes received for a single request exceed this before the parser is done, respond 400 and close.

**Test:** Open a connection, send `"GET "` and wait — should be closed after 5 seconds.

**Files Changed:** `http.h`

---

## Phase 9: Testing & Quality

### Step 22: Comprehensive Parser Edge-Case Tests

**Goal:** Harden the parser with tests for every edge case.

**Test Cases to Add:**
1. Request line at exactly `MAX_REQUEST_LINE_LEN - 1` characters (boundary).
2. Header at exactly `MAX_HEADER_LINE_LEN - 1` characters.
3. Request with `MAX_HEADERS` headers → verify 16th header is stored, 17th is silently dropped.
4. Empty URI: `"GET  HTTP/1.0\r\n\r\n"` → should fail gracefully.
5. Multiple spaces between method/URI/version → per Appendix B, should be tolerated.
6. Header continuation lines (folded headers with leading SP/HT) → per Section 4.2.
7. Header with no value: `"X-Empty:\r\n"` → should parse with empty value.
8. Multiple `Content-Length` headers → should use the first (or reject as 400).
9. `Content-Length: -1` or `Content-Length: abc` → should treat as 0 or reject.
10. Zero-length body: `"POST /x HTTP/1.0\r\nContent-Length: 0\r\n\r\n"` → on_complete should fire.
11. Body longer than advertised `Content-Length` → parser should stop after Content-Length bytes.
12. Request with `\n` line endings instead of `\r\n` → should work (Appendix B tolerance).

**Files Changed:** `tests/test_parser.cpp`

---

### Step 23: Integration Test Suite

**Goal:** Create an automated integration test script that starts the server and exercises all features.

**Implementation:**
1. Create `tests/integration.sh`:
   ```bash
   #!/bin/bash
   set -e
   PORT=18080
   ./build/example $PORT &
   SERVER_PID=$!
   sleep 1
   
   # Test GET
   curl -sf http://localhost:$PORT/index.html > /dev/null
   
   # Test HEAD
   curl -sfI http://localhost:$PORT/index.html | grep "Content-Length"
   
   # Test 404
   curl -sf -o /dev/null -w "%{http_code}" http://localhost:$PORT/nope | grep 404
   
   # Test Conditional GET (304)
   LM=$(curl -sI http://localhost:$PORT/index.html | grep Last-Modified | cut -d' ' -f2-)
   curl -sf -o /dev/null -w "%{http_code}" -H "If-Modified-Since: $LM" http://localhost:$PORT/index.html | grep 304
   
   # Test POST
   curl -sf -X POST -d "hello" http://localhost:$PORT/echo
   
   # Test PUT (if implemented)
   # Test DELETE (if implemented)
   # Test 501 Unknown method
   curl -sf -o /dev/null -w "%{http_code}" -X FOOBAR http://localhost:$PORT/ | grep 501
   
   # Test Basic Auth (if enabled)
   
   # Cleanup
   kill $SERVER_PID
   echo "All integration tests passed!"
   ```
2. Add `integration` target to `Makefile`.

**Files Changed:** `Makefile`  
**New Files:** `tests/integration.sh`

---

### Step 24: Code Coverage to 90%+

**Goal:** Verify that all new code is well-tested.

**Implementation:**
1. Run `make coverage` and check coverage percentage.
2. Identify uncovered branches and add targeted tests.
3. Focus on error paths: malloc failure simulation (if feasible), socket error paths, file read failures.

**Files Changed:** `Makefile`, various test files

---

## Phase 10: Documentation & Release

### Step 25: Update API Documentation

**Goal:** Document every public function, macro, and type.

**Implementation:**
1. Update `README.md`:
   - Add sections for each new API function.
   - Document all configuration macros with defaults.
   - Add examples for each method (GET, HEAD, POST, PUT, DELETE).
   - Add example for Basic Authentication setup.
   - Add example for Conditional GET usage.
2. Add inline documentation comments above each public function declaration in `http.h`.

**Files Changed:** `README.md`, `http.h`

---

### Step 26: Update PLAN.md and Finalize

**Goal:** Mark all completed steps, document any deferred decisions.

**Implementation:**
1. Update `PLAN.md` with checkmarks for all implemented features.
2. Note any features deferred to HTTP/1.1 (e.g., chunked request decoding, Host header requirement, full pipelining).
3. Document the binary size and memory footprint after all features are added.

**Files Changed:** `PLAN.md`

---

## Implementation Order Summary

| Priority | Step | Feature | Depends On |
|----------|------|---------|------------|
| P0 | 1 | Status code reason phrases | — |
| P0 | 2 | HTTP date formatting/parsing | — |
| P0 | 3 | Unified response header builder | 1, 2 |
| P0 | 4 | HEAD method | 3 |
| P0 | 5 | POST/PUT/DELETE + 501 | 3 |
| P1 | 6 | Last-Modified header | 2, 3 |
| P1 | 7 | Expires header | 2, 3 |
| P1 | 8 | Conditional GET (If-Modified-Since / 304) | 2, 6 |
| P1 | 9 | Redirect support (301, 302) | 3 |
| P1 | 10 | Error response HTML bodies | 1, 3 |
| P2 | 11 | Basic Authentication | 3, 10 |
| P2 | 12 | HTTP/0.9 compatibility | 3 |
| P2 | 13 | Pragma: no-cache | — |
| P2 | 14 | Request header logging | 3 |
| P2 | 15 | Allow header | 5 |
| P2 | 16 | Content-Length validation | — |
| P3 | 17 | Content-Encoding / gzip | 3 |
| P3 | 18 | Additional MIME types | — |
| P3 | 19 | Malformed request handling | — |
| P3 | 20 | Rate limiting | — |
| P3 | 21 | Slowloris protection | — |
| P4 | 22 | Parser edge-case tests | — |
| P4 | 23 | Integration test suite | All above |
| P4 | 24 | Code coverage 90%+ | 22, 23 |
| P4 | 25 | API documentation | All above |
| P4 | 26 | Plan finalization | All above |

## Memory Budget Impact

| Feature | RAM Impact | Binary Impact |
|---------|-----------|---------------|
| Status reasons (Step 1) | ~0 (string literals in .rodata) | +200B |
| Date functions (Step 2) | +64B stack per call | +300B |
| Response builder (Step 3) | Replaces existing code | ~0 net |
| HEAD method (Step 4) | +4B per conn (flag) | +100B |
| PUT/DELETE (Step 5) | ~0 (logic only) | +500B |
| If-Modified-Since (Step 8) | +8B per conn (time_t) | +400B |
| Auth (Step 11) | +512B per conn (auth header) | +800B |
| Base64 decode (Step 11) | +64B stack | +200B |
| Rate limiting (Step 20) | +1KB (IP tracker array) | +300B |
| **Total** | **~2KB additional** | **~3KB additional** |

All additions stay well within the <100KB binary, <600KB RAM targets.
