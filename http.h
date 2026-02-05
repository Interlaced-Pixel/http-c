#ifndef HTTP_H
#define HTTP_H

/*
 * HTTP-C: Single-header HTTP server library for embedded systems
 * 
 * This file contains the complete HTTP server implementation.
 * To use, #define HTTP_IMPLEMENTATION before including this file in one .c file.
 *
 * Example:
 *   #define HTTP_IMPLEMENTATION
 *   #include "http.h"
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

/* Configuration */
#ifndef BIND_PORT
#define BIND_PORT 8080
#endif

#ifndef BIND_IP
#define BIND_IP "127.0.0.1"
#endif

#ifndef SERVE_PATH
#define SERVE_PATH "."
#endif

#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 8
#endif

#ifndef READ_BUF_SIZE
#define READ_BUF_SIZE 4096
#endif

#ifndef WRITE_BUF_SIZE
#define WRITE_BUF_SIZE 4096
#endif

#ifndef MAX_HEADERS
#define MAX_HEADERS 16
#endif

#ifndef MAX_HEADER_FIELD_LEN
#define MAX_HEADER_FIELD_LEN 256
#endif

#ifndef MAX_HEADER_VALUE_LEN
#define MAX_HEADER_VALUE_LEN 512
#endif

#ifndef MAX_REQUEST_LINE_LEN
#define MAX_REQUEST_LINE_LEN 4096
#endif

#ifndef MAX_HEADER_LINE_LEN
#define MAX_HEADER_LINE_LEN 4096
#endif

#ifndef CONNECTION_TIMEOUT_SEC
#define CONNECTION_TIMEOUT_SEC 10
#endif

#ifndef ENABLE_KEEP_ALIVE
#define ENABLE_KEEP_ALIVE 1
#endif

#ifndef ENABLE_CHUNKED_ENCODING
#define ENABLE_CHUNKED_ENCODING 0
#endif

#ifndef ENABLE_TLS
#define ENABLE_TLS 0
#endif

#ifndef DEBUG_HTTP
#define DEBUG_HTTP 0
#endif

/* Logging */
typedef enum { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 } log_level_t;
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_DEBUG
#endif
#define LOG(level, fmt, ...) do { if (level <= LOG_LEVEL) fprintf(stderr, "%s: " fmt "\n", (level==LOG_ERROR?"ERR":(level==LOG_WARN?"WRN":(level==LOG_INFO?"INF":"DBG"))), ##__VA_ARGS__); } while(0)

/* Platform detection */
#if defined(__linux__)
#define PLATFORM_LINUX 1
#define PLATFORM_MACOS 0
#define PLATFORM_WINDOWS 0
#define PLATFORM_EMBEDDED 0
#elif defined(__APPLE__)
#define PLATFORM_LINUX 0
#define PLATFORM_MACOS 1
#define PLATFORM_WINDOWS 0
#define PLATFORM_EMBEDDED 0
#elif defined(_WIN32)
#define PLATFORM_LINUX 0
#define PLATFORM_MACOS 0
#define PLATFORM_WINDOWS 1
#define PLATFORM_EMBEDDED 0
#else
#define PLATFORM_LINUX 0
#define PLATFORM_MACOS 0
#define PLATFORM_WINDOWS 0
#define PLATFORM_EMBEDDED 1
#endif

/* Platform includes */
#if PLATFORM_LINUX || PLATFORM_MACOS
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#elif PLATFORM_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>
#define SOCKET_ERROR SOCKET_ERROR
#define INVALID_SOCKET INVALID_SOCKET
#define close closesocket
#define stat _stat
#define mkdir _mkdir
#define access _access
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
#else
#error "Platform not supported. Define socket functions for your RTOS."
#endif

/* Socket type */
#if PLATFORM_WINDOWS
typedef SOCKET socket_t;
#else
typedef int socket_t;
#endif

/* Utility functions */
char *strdup_safe(const char *s);
void str_trim(char *s);

/* Memory pool */
typedef struct {
    void *pool[MAX_CONNECTIONS];
    int used[MAX_CONNECTIONS];
    size_t size;
} mem_pool_t;

void mem_pool_init(mem_pool_t *pool, size_t size);
void *mem_pool_alloc(mem_pool_t *pool);
void mem_pool_free(mem_pool_t *pool, void *ptr);

/* HTTP parser */
typedef enum {
    HTTP_PARSER_REQUEST_LINE,
    HTTP_PARSER_HEADERS,
    HTTP_PARSER_BODY,
    HTTP_PARSER_DONE
} http_parser_state_t;

typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_UNKNOWN
} http_method_t;

typedef struct {
    http_parser_state_t state;
    size_t position;
    int flags;
    char temp_buf[MAX_HEADER_LINE_LEN];
    size_t temp_len;
    int header_field_complete;
    char current_field[MAX_HEADER_FIELD_LEN];
    char current_value[MAX_HEADER_VALUE_LEN];
    void *user_data;
} http_parser_t;

typedef void (*on_request_line_cb)(void *user_data, http_method_t method, const char *uri, const char *version);
typedef void (*on_header_cb)(void *user_data, const char *field, const char *value);
typedef void (*on_body_cb)(void *user_data, const char *data, size_t len);
typedef void (*on_complete_cb)(void *user_data);
typedef void (*on_headers_complete_cb)(void *user_data);

typedef struct {
    on_request_line_cb on_request_line;
    on_header_cb on_header;
    on_body_cb on_body;
    on_headers_complete_cb on_headers_complete;
    on_complete_cb on_complete;
} http_parser_settings_t;

void http_parser_init(http_parser_t *parser);
size_t http_parser_execute(http_parser_t *parser, const http_parser_settings_t *settings, const char *data, size_t len);
int http_parser_is_done(const http_parser_t *parser);
void http_parser_reset(http_parser_t *parser);
http_method_t http_method_from_string(const char *method);
const char *http_method_to_string(http_method_t method);

/* HTTP server */
typedef struct http_conn http_conn_t;
typedef struct http_server http_server_t;

typedef struct {
    char field[MAX_HEADER_FIELD_LEN];
    char value[MAX_HEADER_VALUE_LEN];
} http_header_t;

struct http_conn {
    socket_t sock;
    char read_buf[READ_BUF_SIZE];
    size_t read_len;
    char write_buf[WRITE_BUF_SIZE];
    size_t write_len;
    http_parser_t parser;
    http_parser_settings_t parser_settings;
    http_header_t headers[MAX_HEADERS];
    size_t header_count;
    unsigned long last_active;
    int keep_alive;
    http_method_t method;
    char uri[256];
    void (*on_request)(http_conn_t *conn, http_method_t method, const char *uri);
    /* Body buffering for requests with Content-Length */
    char body_buf[READ_BUF_SIZE];
    size_t body_len;
    size_t expected_content_length;
    /* Upload streaming to temp file when body is large */
    FILE *upload_fp;
    char upload_path[256];
};

struct http_server {
    socket_t listen_sock;
    http_conn_t connections[MAX_CONNECTIONS];
    int conn_count;
    volatile int running;
};

int http_server_init(http_server_t *server, const char *ip, int port);
void http_server_run(http_server_t *server);
void http_server_stop(http_server_t *server);
void http_server_close(http_server_t *server);
void http_conn_init(http_conn_t *conn);
void http_conn_close(http_conn_t *conn);
int http_conn_send_response(http_conn_t *conn, int status, const char *body);
void http_server_set_request_handler(http_server_t *server, void (*handler)(http_conn_t *conn, http_method_t method, const char *uri));

/* Socket functions */
int socket_create(int family, int type, int protocol);
int socket_bind(socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
int socket_listen(socket_t sock, int backlog);
socket_t socket_accept(socket_t sock, struct sockaddr *addr, socklen_t *addrlen);
int socket_connect(socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
int socket_nonblocking(socket_t sock);
ssize_t socket_recv(socket_t sock, void *buf, size_t len, int flags);
ssize_t socket_send(socket_t sock, const void *buf, size_t len, int flags);
static ssize_t socket_send_all(socket_t sock, const void *buf, size_t len);
int socket_close(socket_t sock);
unsigned long get_time_ms(void);
int get_last_error(void);
char *strerror_platform(int err);

/* File I/O functions */
typedef struct {
    char *data;
    size_t size;
} file_content_t;

int file_exists(const char *path);
int file_read(const char *path, file_content_t *content);
void file_free(file_content_t *content);
const char *mime_type_from_path(const char *path);
void url_decode(char *dst, const char *src, size_t dst_size);
int path_is_safe(const char *path);

/* HTTP response functions */
int http_conn_send_file(http_conn_t *conn, int status, const char *path);
int http_conn_send_directory_listing(http_conn_t *conn, const char *path, const char *uri_path);

#endif /* HTTP_H */

#ifdef HTTP_IMPLEMENTATION

/* Utility implementation */
char *strdup_safe(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *dup = malloc(len + 1);
    if (dup) {
        memcpy(dup, s, len + 1);
    }
    return dup;
}

void str_trim(char *s) {
    if (!s) return;
    char *start = s;
    while (*start && isspace(*start)) start++;
    char *end = start + strlen(start) - 1;
    while (end > start && isspace(*end)) *end-- = '\0';
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
}

/* Memory pool implementation */
void mem_pool_init(mem_pool_t *pool, size_t size) {
    memset(pool, 0, sizeof(*pool));
    pool->size = size;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        pool->pool[i] = malloc(size);
        pool->used[i] = 0;
    }
}

void *mem_pool_alloc(mem_pool_t *pool) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!pool->used[i]) {
            pool->used[i] = 1;
            return pool->pool[i];
        }
    }
    return NULL;
}

void mem_pool_free(mem_pool_t *pool, void *ptr) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (pool->pool[i] == ptr) {
            pool->used[i] = 0;
            memset(ptr, 0, pool->size);
            break;
        }
    }
}

/* HTTP parser implementation */
void http_parser_init(http_parser_t *parser) {
    memset(parser, 0, sizeof(*parser));
    parser->state = HTTP_PARSER_REQUEST_LINE;
}

size_t http_parser_execute(http_parser_t *parser, const http_parser_settings_t *settings, const char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        char c = data[i];
        switch (parser->state) {
            case HTTP_PARSER_REQUEST_LINE: {
                if (c == '\r') {
                    parser->temp_buf[parser->temp_len] = '\0';
                    char *method_str = strtok(parser->temp_buf, " ");
                    char *uri = strtok(NULL, " ");
                    char *version = strtok(NULL, " ");
                    if (method_str && uri && version) {
                        http_method_t method = http_method_from_string(method_str);
                        if (settings->on_request_line) {
                            settings->on_request_line(parser->user_data, method, uri, version);
                        }
                        parser->state = HTTP_PARSER_HEADERS;
                        parser->temp_len = 0;
                    } else {
                        return i;
                    }
                } else if (c != '\n') {
                    if (parser->temp_len < MAX_REQUEST_LINE_LEN - 1) {
                        parser->temp_buf[parser->temp_len++] = c;
                    } else {
                        return i;
                    }
                }
                break;
            }
            case HTTP_PARSER_HEADERS: {
                if (c == '\r') {
                    parser->temp_buf[parser->temp_len] = '\0';
                    if (parser->temp_len == 0) {
                        parser->state = HTTP_PARSER_BODY;
                        if (settings->on_headers_complete) {
                            settings->on_headers_complete(parser->user_data);
                        }
                    } else {
                        char *colon = strchr(parser->temp_buf, ':');
                        if (colon) {
                            *colon = '\0';
                            char *field = parser->temp_buf;
                            char *value = colon + 1;
                            while (*value && isspace(*value)) value++;
                            size_t value_len = strlen(value);
                            while (value_len > 0 && isspace(value[value_len - 1])) {
                                value[--value_len] = '\0';
                            }
                            if (settings->on_header) {
                                settings->on_header(parser->user_data, field, value);
                            }
                        }
                        parser->temp_len = 0;
                    }
                } else if (c != '\n') {
                    if (parser->temp_len < MAX_HEADER_LINE_LEN - 1) {
                        parser->temp_buf[parser->temp_len++] = c;
                    } else {
                        return i;
                    }
                }
                break;
            }
            case HTTP_PARSER_BODY: {
                if (settings->on_body) {
                    settings->on_body(parser->user_data, &c, 1);
                }
                break;
            }
            case HTTP_PARSER_DONE:
                return i;
        }
        i++;
    }
    return i;
}

int http_parser_is_done(const http_parser_t *parser) {
    return parser->state == HTTP_PARSER_DONE;
}

void http_parser_reset(http_parser_t *parser) {
    void *ud = NULL;
    if (parser) ud = parser->user_data;
    http_parser_init(parser);
    parser->user_data = ud;
}

http_method_t http_method_from_string(const char *method) {
    if (strcmp(method, "GET") == 0) return HTTP_METHOD_GET;
    if (strcmp(method, "POST") == 0) return HTTP_METHOD_POST;
    if (strcmp(method, "PUT") == 0) return HTTP_METHOD_PUT;
    if (strcmp(method, "DELETE") == 0) return HTTP_METHOD_DELETE;
    if (strcmp(method, "HEAD") == 0) return HTTP_METHOD_HEAD;
    if (strcmp(method, "OPTIONS") == 0) return HTTP_METHOD_OPTIONS;
    if (strcmp(method, "PATCH") == 0) return HTTP_METHOD_PATCH;
    return HTTP_METHOD_UNKNOWN;
}

const char *http_method_to_string(http_method_t method) {
    switch (method) {
        case HTTP_METHOD_GET: return "GET";
        case HTTP_METHOD_POST: return "POST";
        case HTTP_METHOD_PUT: return "PUT";
        case HTTP_METHOD_DELETE: return "DELETE";
        case HTTP_METHOD_HEAD: return "HEAD";
        case HTTP_METHOD_OPTIONS: return "OPTIONS";
        case HTTP_METHOD_PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}

/* HTTP server implementation */
static void on_request_line(void *user_data, http_method_t method, const char *uri, const char *version) {
    http_conn_t *conn = (http_conn_t *)user_data;
    conn->method = method;
    strncpy(conn->uri, uri, sizeof(conn->uri) - 1);
    conn->uri[sizeof(conn->uri) - 1] = '\0';
    /* Default keep-alive behavior: HTTP/1.1 defaults to keep-alive */
    if (version && strcmp(version, "HTTP/1.1") == 0) {
        conn->keep_alive = 1;
    } else {
        conn->keep_alive = 0;
    }
    LOG(LOG_DEBUG, "on_request_line: uri=%s version=%s keep_alive=%d fd=%d", conn->uri, version?version:"(null)", conn->keep_alive, conn->sock);
}


static void on_header(void *user_data, const char *field, const char *value) {
    http_conn_t *conn = (http_conn_t *)user_data;
    if (!conn || !field || !value) return;
    if (conn->header_count < MAX_HEADERS) {
        strncpy(conn->headers[conn->header_count].field, field, MAX_HEADER_FIELD_LEN - 1);
        conn->headers[conn->header_count].field[MAX_HEADER_FIELD_LEN - 1] = '\0';
        strncpy(conn->headers[conn->header_count].value, value, MAX_HEADER_VALUE_LEN - 1);
        conn->headers[conn->header_count].value[MAX_HEADER_VALUE_LEN - 1] = '\0';
        conn->header_count++;
    }
}

static void on_body(void *user_data, const char *data, size_t len) {
    http_conn_t *conn = (http_conn_t *)user_data;
    if (!conn || !data || len == 0) return;
    /* If an upload file is open, stream to it */
    if (conn->upload_fp) {
        size_t written = fwrite(data, 1, len, conn->upload_fp);
        if (written != len) {
            LOG(LOG_WARN, "failed to write upload data (%zu/%zu)", written, len);
        }
        conn->body_len += written;
        return;
    }

    /* Append up to buffer capacity; if overflow, open temp file and flush */
    size_t free_space = sizeof(conn->body_buf) - conn->body_len;
    if (len <= free_space) {
        memcpy(conn->body_buf + conn->body_len, data, len);
        conn->body_len += len;
        return;
    }

    /* Need to spill to temp file */
    /* Create upload file */
    snprintf(conn->upload_path, sizeof(conn->upload_path), "%s/.upload_%d_%ld.tmp", SERVE_PATH, (int)conn->sock, (long)get_time_ms());
    conn->upload_fp = fopen(conn->upload_path, "wb");
    if (!conn->upload_fp) {
        LOG(LOG_ERROR, "failed to open upload file %s", conn->upload_path);
        return;
    }
    /* write existing buffer first */
    if (conn->body_len > 0) {
        fwrite(conn->body_buf, 1, conn->body_len, conn->upload_fp);
    }
    /* write incoming data */
    fwrite(data, 1, len, conn->upload_fp);
    conn->body_len += len;
}

static void on_headers_complete(void *user_data) {
    http_conn_t *conn = (http_conn_t *)user_data;
    if (!conn) return;
    conn->expected_content_length = 0;
    conn->body_len = 0;
    /* Look for Content-Length and Connection headers */
    for (size_t i = 0; i < conn->header_count; i++) {
        const char *f = conn->headers[i].field;
        const char *v = conn->headers[i].value;
        if (!f || !v) continue;
        /* Case-insensitive compare for header names */
        if (strcasecmp(f, "Content-Length") == 0) {
            conn->expected_content_length = (size_t)atoi(v);
            if (conn->expected_content_length > sizeof(conn->body_buf)) {
                /* Too large for our buffer */
                LOG(LOG_INFO, "Content-Length %zu exceeds buffer, will stream to disk", conn->expected_content_length);
                /* prepare upload path but do not open yet until body arrives */
                conn->upload_fp = NULL;
                conn->upload_path[0] = '\0';
            }
        } else if (strcasecmp(f, "Connection") == 0) {
            if (strcasecmp(v, "keep-alive") == 0) conn->keep_alive = 1;
            else conn->keep_alive = 0;
            LOG(LOG_DEBUG, "on_headers_complete: Connection: %s -> keep_alive=%d fd=%d", v, conn->keep_alive, conn->sock);
        }
    }

    /* If no body expected, trigger request immediately */
    if (conn->expected_content_length == 0) {
        if (conn->on_request) conn->on_request(conn, conn->method, conn->uri);
        http_parser_reset(&conn->parser);
    }
}

static void on_complete(void *user_data) {
    http_conn_t *conn = (http_conn_t *)user_data;
    if (!conn) return;
    /* Only call on_request when full body received */
    if (conn->expected_content_length == 0 || conn->body_len >= conn->expected_content_length) {
        if (conn->on_request) conn->on_request(conn, conn->method, conn->uri);
        /* close upload file if open */
        if (conn->upload_fp) {
            fflush(conn->upload_fp);
            fclose(conn->upload_fp);
            conn->upload_fp = NULL;
        }
        http_parser_reset(&conn->parser);
    }
}

int http_server_init(http_server_t *server, const char *ip, int port) {
    memset(server, 0, sizeof(*server));
    server->running = 0;

    server->listen_sock = socket_create(AF_INET, SOCK_STREAM, 0);
    if (server->listen_sock == INVALID_SOCKET) {
        LOG(LOG_ERROR, "socket_create failed: %d", get_last_error());
        return -1;
    }
    /* Ignore SIGPIPE so writing to closed sockets doesn't terminate process */
#if !PLATFORM_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif
    /* Allow quick reuse of address/port */
    {
        int opt = 1;
        setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#if defined(SO_REUSEPORT)
        setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (strcmp(ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        socket_close(server->listen_sock);
        return -1;
    }
    addr.sin_port = htons(port);
    if (socket_bind(server->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOG(LOG_ERROR, "socket_bind failed: %d", get_last_error());
        socket_close(server->listen_sock);
        return -1;
    }

    if (socket_listen(server->listen_sock, 16) != 0) {
        LOG(LOG_ERROR, "socket_listen failed: %d", get_last_error());
        socket_close(server->listen_sock);
        return -1;
    }

    if (socket_nonblocking(server->listen_sock) != 0) {
        LOG(LOG_ERROR, "socket_nonblocking failed: %d", get_last_error());
        socket_close(server->listen_sock);
        return -1;
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        http_conn_init(&server->connections[i]);
    }

    server->running = 1;
    LOG(LOG_INFO, "server initialized (fd=%d)", server->listen_sock);
    return 0;
}

void http_server_run(http_server_t *server) {
    fd_set read_fds;
    int max_fd = server->listen_sock;
    while (server->running) {
        FD_ZERO(&read_fds);
        FD_SET(server->listen_sock, &read_fds);

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            http_conn_t *conn = &server->connections[i];
            if (conn->sock != INVALID_SOCKET) {
                FD_SET(conn->sock, &read_fds);
                if (conn->sock > max_fd) max_fd = conn->sock;
            }
        }

        struct timeval tv = {1, 0};
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG(LOG_WARN, "select failed: %d", get_last_error());
            continue;
        }

        if (FD_ISSET(server->listen_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            socket_t client_sock = socket_accept(server->listen_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock != INVALID_SOCKET) {
                socket_nonblocking(client_sock);
                int added = 0;
                for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (server->connections[i].sock == INVALID_SOCKET) {
                        server->connections[i].sock = client_sock;
                        server->connections[i].last_active = get_time_ms();
                        server->conn_count++;
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    LOG(LOG_WARN, "connection refused: max connections reached");
                    socket_close(client_sock);
                }
            } else {
                int err = get_last_error();
                if (err != EWOULDBLOCK && err != EAGAIN) {
                    LOG(LOG_WARN, "accept returned INVALID_SOCKET: %d", err);
                }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            http_conn_t *conn = &server->connections[i];
            if (conn->sock != INVALID_SOCKET && FD_ISSET(conn->sock, &read_fds)) {
                ssize_t n = socket_recv(conn->sock, conn->read_buf + conn->read_len, READ_BUF_SIZE - conn->read_len, 0);
                if (n > 0) {
                    conn->read_len += n;
                    conn->last_active = get_time_ms();
                    size_t parsed = http_parser_execute(&conn->parser, &conn->parser_settings, conn->read_buf, conn->read_len);
                    if (parsed < conn->read_len) {
                        memmove(conn->read_buf, conn->read_buf + parsed, conn->read_len - parsed);
                        conn->read_len -= parsed;
                    } else {
                        conn->read_len = 0;
                    }
                } else if (n == 0) {
                    LOG(LOG_INFO, "client closed connection (fd=%d)", conn->sock);
                    http_conn_close(conn);
                    server->conn_count--;
                } else {
                    int err = get_last_error();
                    if (err == EWOULDBLOCK || err == EAGAIN) {
                        continue;
                    }
                    LOG(LOG_WARN, "recv error on fd=%d: %d", conn->sock, err);
                    http_conn_close(conn);
                    server->conn_count--;
                }
            }
        }

        unsigned long now = get_time_ms();
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            http_conn_t *conn = &server->connections[i];
            if (conn->sock != INVALID_SOCKET && (now - conn->last_active) > (CONNECTION_TIMEOUT_SEC * 1000)) {
                LOG(LOG_INFO, "connection timeout (fd=%d)", conn->sock);
                http_conn_close(conn);
                server->conn_count--;
            }
        }
    }
}

void http_server_stop(http_server_t *server) {
    if (!server) return;
    server->running = 0;
    LOG(LOG_INFO, "server stopping");
}

void http_server_close(http_server_t *server) {
    socket_close(server->listen_sock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (server->connections[i].sock != INVALID_SOCKET) {
            http_conn_close(&server->connections[i]);
        }
    }
}

void http_conn_init(http_conn_t *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->sock = INVALID_SOCKET;
    http_parser_init(&conn->parser);
    conn->parser.user_data = conn;
    conn->parser_settings.on_request_line = on_request_line;
    conn->parser_settings.on_header = on_header;
    conn->parser_settings.on_body = on_body;
    conn->parser_settings.on_headers_complete = on_headers_complete;
    conn->parser_settings.on_complete = on_complete;
    conn->body_len = 0;
    conn->expected_content_length = 0;
}

void http_conn_close(http_conn_t *conn) {
    if (conn->sock != INVALID_SOCKET) {
        socket_close(conn->sock);
        conn->sock = INVALID_SOCKET;
    }
}

int http_conn_send_response(http_conn_t *conn, int status, const char *body) {
    if (!conn || conn->sock == INVALID_SOCKET) return -1;
    char header[WRITE_BUF_SIZE];
    size_t body_len = body ? strlen(body) : 0;
    int hlen = snprintf(header, sizeof(header), "HTTP/1.0 %d OK\r\nContent-Length: %zu\r\nContent-Type: text/plain\r\nConnection: %s\r\n\r\n", status, body_len, conn->keep_alive ? "keep-alive" : "close");
    if (hlen < 0 || hlen >= (int)sizeof(header)) return -1;

    ssize_t sent = socket_send_all(conn->sock, header, hlen);
    if (sent != hlen) {
        LOG(LOG_WARN, "send header failed on fd=%d: %zd/%d", conn->sock, sent, hlen);
        http_conn_close(conn);
        return -1;
    }
    if (body_len > 0) {
        sent = socket_send_all(conn->sock, body, body_len);
        if (sent != (ssize_t)body_len) {
            LOG(LOG_WARN, "send body failed on fd=%d: %zd/%zu", conn->sock, sent, body_len);
            http_conn_close(conn);
            return -1;
        }
    }

    /* If keep-alive requested, reset parser and state for next request and keep socket open */
    if (conn->keep_alive) {
        /* Prevent simple pipelining: if there's unread data buffered, close instead */
        if (conn->read_len > 0) {
            LOG(LOG_INFO, "pipelining detected, closing connection fd=%d", conn->sock);
            http_conn_close(conn);
            return 0;
        }

        conn->last_active = get_time_ms();
        conn->header_count = 0;
        conn->body_len = 0;
        conn->expected_content_length = 0;
        if (conn->upload_fp) {
            fclose(conn->upload_fp);
            conn->upload_fp = NULL;
        }
        http_parser_reset(&conn->parser);
        return 0;
    }

    http_conn_close(conn);
    return 0;
}

void http_server_set_request_handler(http_server_t *server, void (*handler)(http_conn_t *conn, http_method_t method, const char *uri)) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        server->connections[i].on_request = handler;
    }
}

/* Socket implementation */
int socket_create(int family, int type, int protocol) {
#if PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return INVALID_SOCKET;
#endif
    return socket(family, type, protocol);
}

int socket_bind(socket_t sock, const struct sockaddr *addr, socklen_t addrlen) {
    return bind(sock, addr, addrlen);
}

int socket_listen(socket_t sock, int backlog) {
    return listen(sock, backlog);
}

socket_t socket_accept(socket_t sock, struct sockaddr *addr, socklen_t *addrlen) {
    return accept(sock, addr, addrlen);
}

int socket_connect(socket_t sock, const struct sockaddr *addr, socklen_t addrlen) {
    return connect(sock, addr, addrlen);
}

int socket_nonblocking(socket_t sock) {
#if PLATFORM_WINDOWS
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

ssize_t socket_recv(socket_t sock, void *buf, size_t len, int flags) {
    return recv(sock, buf, len, flags);
}

ssize_t socket_send(socket_t sock, const void *buf, size_t len, int flags) {
    return send(sock, buf, len, flags);
}

static ssize_t socket_send_all(socket_t sock, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = (const char *)buf;
    while (total < len) {
        ssize_t n = socket_send(sock, p + total, len - total, 0);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) return (ssize_t)total;
        int err = get_last_error();
        if (err == EAGAIN || err == EWOULDBLOCK) {
            /* wait until socket writable */
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv = {1, 0};
            int sel = select((int)sock + 1, NULL, &wfds, NULL, &tv);
            if (sel <= 0) return -1;
            continue;
        }
        return -1;
    }
    return (ssize_t)total;
}

int socket_close(socket_t sock) {
#if PLATFORM_WINDOWS
    closesocket(sock);
    WSACleanup();
    return 0;
#else
    return close(sock);
#endif
}

unsigned long get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int get_last_error(void) {
#if PLATFORM_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif
}

char *strerror_platform(int err) {
    return strerror(err);
}

/* File I/O implementation */
int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

int file_read(const char *path, file_content_t *content) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0) {
        fclose(fp);
        return -1;
    }

    content->data = malloc(size + 1);
    if (!content->data) {
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(content->data, 1, size, fp);
    if (read_size != (size_t)size) {
        free(content->data);
        fclose(fp);
        return -1;
    }

    content->data[size] = '\0';
    content->size = size;
    fclose(fp);
    return 0;
}

void file_free(file_content_t *content) {
    if (content->data) {
        free(content->data);
        content->data = NULL;
        content->size = 0;
    }
}

const char *mime_type_from_path(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";

    ext++; // Skip the dot

    if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0) return "text/html";
    if (strcmp(ext, "css") == 0) return "text/css";
    if (strcmp(ext, "js") == 0) return "application/javascript";
    if (strcmp(ext, "json") == 0) return "application/json";
    if (strcmp(ext, "xml") == 0) return "application/xml";
    if (strcmp(ext, "txt") == 0) return "text/plain";
    if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, "png") == 0) return "image/png";
    if (strcmp(ext, "gif") == 0) return "image/gif";
    if (strcmp(ext, "svg") == 0) return "image/svg+xml";
    if (strcmp(ext, "ico") == 0) return "image/x-icon";
    if (strcmp(ext, "pdf") == 0) return "application/pdf";
    if (strcmp(ext, "zip") == 0) return "application/zip";
    if (strcmp(ext, "gz") == 0) return "application/gzip";

    return "application/octet-stream";
}

void url_decode(char *dst, const char *src, size_t dst_size) {
    size_t i = 0, j = 0;
    while (src[i] && j < dst_size - 1) {
        if (src[i] == '%' && src[i+1] && src[i+2]) {
            char hex[3] = {src[i+1], src[i+2], '\0'};
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
}

int path_is_safe(const char *path) {
    // Check for directory traversal attempts
    if (strstr(path, "..") != NULL) return 0;

    // Check for absolute paths
    if (path[0] == '/' || path[0] == '\\') return 0;

    // Check for drive letters (Windows)
    if (strlen(path) >= 3 && path[1] == ':' && (path[2] == '/' || path[2] == '\\')) return 0;

    return 1;
}

int http_conn_send_file(http_conn_t *conn, int status, const char *path) {
    file_content_t content;
    if (file_read(path, &content) != 0) {
        return http_conn_send_response(conn, 404, "File not found");
    }

    const char *mime_type = mime_type_from_path(path);
    char response[WRITE_BUF_SIZE];
    int len = snprintf(response, sizeof(response),
                      "HTTP/1.0 %d OK\r\n"
                      "Content-Type: %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: %s\r\n"
                      "\r\n",
                      status, mime_type, content.size, conn->keep_alive ? "keep-alive" : "close");

    if (len >= (int)sizeof(response)) {
        file_free(&content);
        return http_conn_send_response(conn, 500, "Response header too large");
    }

    // Send header
    ssize_t sent = socket_send_all(conn->sock, response, len);
    if (sent != len) {
        file_free(&content);
        http_conn_close(conn);
        return -1;
    }

    // Send file content
    size_t csize = content.size;
    /* reuse send-all helper defined in response function */
    extern ssize_t socket_send_all(socket_t sock, const void *buf, size_t len);
    sent = socket_send_all(conn->sock, content.data, csize);
    file_free(&content);

    if (sent != (ssize_t)csize) {
        LOG(LOG_WARN, "send file content failed on fd=%d: %zd/%zu", conn->sock, sent, csize);
        http_conn_close(conn);
        return -1;
    }

    if (conn->keep_alive) {
        conn->last_active = get_time_ms();
        conn->header_count = 0;
        conn->body_len = 0;
        conn->expected_content_length = 0;
        http_parser_reset(&conn->parser);
        return 0;
    }

    http_conn_close(conn);
    return 0;
}

int http_conn_send_directory_listing(http_conn_t *conn, const char *path, const char *uri_path) {
    DIR *dir = opendir(path);
    if (!dir) {
        return http_conn_send_response(conn, 403, "Directory access denied");
    }

    char html[WRITE_BUF_SIZE];
    int html_len = snprintf(html, sizeof(html),
                           "<!DOCTYPE html><html><head><title>Directory Listing</title></head><body>"
                           "<h1>Directory: %s</h1><ul>", uri_path);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && html_len < (int)sizeof(html) - 256) {
        if (strcmp(entry->d_name, ".") == 0) continue;

        const char *type = (entry->d_type == DT_DIR) ? "/" : "";
        html_len += snprintf(html + html_len, sizeof(html) - html_len,
                           "<li><a href=\"%s%s\">%s%s</a></li>",
                           entry->d_name, type, entry->d_name, type);
    }
    closedir(dir);

    html_len += snprintf(html + html_len, sizeof(html) - html_len, "</ul></body></html>");

    char response[WRITE_BUF_SIZE];
    int len = snprintf(response, sizeof(response),
                      "HTTP/1.0 200 OK\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: %d\r\n"
                      "Connection: %s\r\n"
                      "\r\n",
                      html_len, conn->keep_alive ? "keep-alive" : "close");

    if (len >= (int)sizeof(response) || html_len >= (int)sizeof(html)) {
        return http_conn_send_response(conn, 500, "Directory listing too large");
    }

    // Send header
    ssize_t sent = socket_send_all(conn->sock, response, len);
    if (sent != len) {
        http_conn_close(conn);
        return -1;
    }

    // Send HTML content
    extern ssize_t socket_send_all(socket_t sock, const void *buf, size_t len);
    sent = socket_send_all(conn->sock, html, html_len);
    if (sent != html_len) {
        LOG(LOG_WARN, "send html failed on fd=%d: %zd/%d", conn->sock, sent, html_len);
        http_conn_close(conn);
        return -1;
    }

    if (conn->keep_alive) {
        conn->last_active = get_time_ms();
        conn->header_count = 0;
        conn->body_len = 0;
        conn->expected_content_length = 0;
        http_parser_reset(&conn->parser);
        return 0;
    }

    http_conn_close(conn);
    return 0;
}

#endif /* HTTP_IMPLEMENTATION */