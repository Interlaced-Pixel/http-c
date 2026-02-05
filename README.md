# HTTP-C: Single-Header HTTP Server Library

A minimal, memory-efficient HTTP/1.0 server library for embedded systems, condensed into a single header file.

## Features

- **Single Header**: Drop `http.h` into your project and `#define HTTP_IMPLEMENTATION` in one .c file
- **Memory Efficient**: Static connection pools, no heap allocation in request loop
- **Event-Driven**: Single-threaded with `select()`, suitable for embedded
- **Portable**: Works on Linux, macOS, Windows, and RTOS (with minor modifications)
- **HTTP/1.0**: Request line and header parsing, with Keep-Alive support

## Quick Start

1. Download `http.h`
2. Create your main.c:

```c
#define HTTP_IMPLEMENTATION
#include "http.h"

static void request_handler(http_conn_t *conn, http_method_t method, const char *uri) {
    if (strcmp(uri, "/hello") == 0 && method == HTTP_METHOD_GET) {
        http_conn_send_response(conn, 200, "Hello World!");
    } else {
        http_conn_send_response(conn, 404, "Not Found");
    }
}

int main() {
    http_server_t server;
    http_server_init(&server, 8080);
    http_server_set_request_handler(&server, request_handler);
    http_server_run(&server);  // Runs forever
    return 0;
}
```

3. Compile: `gcc main.c -o server`
4. Run: `./server`
5. Test: `curl http://localhost:8080/`

Output:
```
Server listening on 0.0.0.0:8080
Serving from: .
Try: curl http://localhost:8080/
```

The server now serves files from the `SERVE_PATH` directory. Place HTML, CSS, JS, and other files in the current directory (or set `SERVE_PATH` to another directory).

## Features

- **File Serving**: Serves static files with proper MIME types
- **Directory Listing**: Shows file listings for directories without index.html
- **Security**: Prevents directory traversal attacks
- **URL Decoding**: Handles URL-encoded characters
- **Embedded Optimized**: Uses static memory pools, no dynamic allocation in request path

## Configuration

Define these before including `http.h` to customize:

```c
#define BIND_PORT 8080           // Default server port
#define BIND_IP "0.0.0.0"        // IP address to bind to
#define SERVE_PATH "."           // Root directory for static files
#define MAX_CONNECTIONS 8        // Max concurrent connections
#define READ_BUF_SIZE 4096       // Per-connection read buffer
#define WRITE_BUF_SIZE 4096      // Per-connection write buffer
#define CONNECTION_TIMEOUT_SEC 10 // Idle timeout
```

## API Reference

### Server Functions

- `int http_server_init(http_server_t *server, int port)` - Initialize server
- `void http_server_run(http_server_t *server)` - Run event loop (blocking)
- `void http_server_close(http_server_t *server)` - Cleanup
- `void http_server_set_request_handler(http_server_t *server, handler)` - Set request callback

### Connection Functions

- `int http_conn_send_response(http_conn_t *conn, int status, const char *body)` - Send HTTP response

### Types

- `http_server_t` - Server instance
- `http_conn_t` - Connection instance
- `http_method_t` - HTTP methods (GET, POST, etc.)

## Memory Usage

- **Per Connection**: ~5KB (buffers + parser state)
- **Total (8 connections)**: ~40KB + TCP stack
- **Binary Size**: ~30KB (stripped)

## Limitations

- HTTP/1.0 only (no chunked encoding, no HTTP/2)
- No TLS (add mbedTLS separately)
- Single-threaded (use external process manager for multi-core)

## License

MIT License - Free for commercial and personal use.