#ifndef HTTP_H
#define HTTP_H

/* Feature test macros for POSIX/GNU extensions */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * HTTP-C: Single-header HTTP server library for embedded systems
 *
 * This file contains the complete HTTP server implementation.
 * To use, #define HTTP_IMPLEMENTATION before including this file in one .c
 * file.
 *
 * Example:
 *   #define HTTP_IMPLEMENTATION
 *   #include "http.h"
 */

#include <ctype.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#ifndef MAX_URI_LEN
#define MAX_URI_LEN 1024
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

#ifndef DIRECTORY_LISTING
#define DIRECTORY_LISTING 1
#endif

/* Logging */
typedef enum {
  LOG_ERROR = 0,
  LOG_WARN = 1,
  LOG_INFO = 2,
  LOG_DEBUG = 3
} log_level_t;
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_INFO
#endif
#define LOG(level, fmt, ...)                                                   \
  do {                                                                         \
    if (level <= LOG_LEVEL)                                                    \
      fprintf(                                                                 \
          stderr, "%s: " fmt "\n",                                             \
          (level == LOG_ERROR                                                  \
               ? "ERR"                                                         \
               : (level == LOG_WARN ? "WRN"                                    \
                                    : (level == LOG_INFO ? "INF" : "DBG"))),   \
          ##__VA_ARGS__);                                                      \
  } while (0)

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
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#elif PLATFORM_WINDOWS
#include <direct.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
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
  size_t content_length;
  size_t body_received;
  int headers_started;
  int blank_line;
  void *user_data;
} http_parser_t;

typedef void (*on_request_line_cb)(void *user_data, http_method_t method,
                                   const char *uri, const char *version);
typedef void (*on_header_cb)(void *user_data, const char *field,
                             const char *value);
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
size_t http_parser_execute(http_parser_t *parser,
                           const http_parser_settings_t *settings,
                           const char *data, size_t len);
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
int http_conn_start_chunked_response(http_conn_t *conn, int status,
                                     const char *content_type);
int http_conn_send_chunk(http_conn_t *conn, const char *data, size_t len);
int http_conn_end_chunked_response(http_conn_t *conn);
void http_server_set_request_handler(http_server_t *server,
                                     void (*handler)(http_conn_t *conn,
                                                     http_method_t method,
                                                     const char *uri));

/* Socket functions */
int socket_create(int family, int type, int protocol);
int socket_bind(socket_t sock, const struct sockaddr *addr, socklen_t addrlen);
int socket_listen(socket_t sock, int backlog);
socket_t socket_accept(socket_t sock, struct sockaddr *addr,
                       socklen_t *addrlen);
int socket_connect(socket_t sock, const struct sockaddr *addr,
                   socklen_t addrlen);
int socket_nonblocking(socket_t sock);
ssize_t socket_recv(socket_t sock, void *buf, size_t len, int flags);
ssize_t socket_send(socket_t sock, const void *buf, size_t len, int flags);
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
int is_directory(const char *path);
int file_read(const char *path, file_content_t *content);
void file_free(file_content_t *content);
const char *mime_type_from_path(const char *path);
void url_decode(char *dst, const char *src, size_t dst_size);
int path_normalize(char *dst, const char *src, size_t dst_size);
int path_is_safe(const char *path);

/* HTTP response functions */
int http_conn_send_file(http_conn_t *conn, int status, const char *path);
int http_conn_send_directory_listing(http_conn_t *conn, const char *path,
                                     const char *uri_path);
int http_conn_send_error(http_conn_t *conn, int status, const char *msg);
int http_conn_send_redirect(http_conn_t *conn, int status,
                            const char *location);

#ifndef HTTP_SERVER_NAME
#define HTTP_SERVER_NAME "HTTP-C/1.0"
#endif

const char *http_status_reason(int status);
int http_format_date(char *buf, size_t buf_size, time_t t);
time_t http_parse_date(const char *str);

#endif /* HTTP_H */

#ifdef HTTP_IMPLEMENTATION

/* Utility implementation */
static ssize_t socket_send_all(socket_t sock, const void *buf, size_t len);

char *strdup_safe(const char *s) {
  if (!s)
    return NULL;
  size_t len = strlen(s);
  char *dup = malloc(len + 1);
  if (dup) {
    memcpy(dup, s, len + 1);
  }
  return dup;
}

void str_trim(char *s) {
  if (!s)
    return;
  char *start = s;
  while (*start && isspace(*start))
    start++;
  char *end = start + strlen(start) - 1;
  while (end > start && isspace(*end))
    *end-- = '\0';
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

size_t http_parser_execute(http_parser_t *parser,
                           const http_parser_settings_t *settings,
                           const char *data, size_t len) {
  size_t i = 0;
  while (i < len) {
    if (parser->state == HTTP_PARSER_DONE)
      return i;

    char c = data[i];
    switch (parser->state) {
    case HTTP_PARSER_REQUEST_LINE:
      if (c == '\r') {
        parser->temp_buf[parser->temp_len] = '\0';
        char *method_str = strtok(parser->temp_buf, " ");
        char *uri = strtok(NULL, " ");
        char *version = strtok(NULL, " ");
        if (method_str && uri && version) {
          if (settings->on_request_line) {
            settings->on_request_line(parser->user_data,
                                      http_method_from_string(method_str), uri,
                                      version);
          }
          parser->state = HTTP_PARSER_HEADERS;
          parser->temp_len = 0;
          parser->headers_started = 0;
        } else {
          return i;
        }
      } else if (c != '\n') {
        if (parser->temp_len < MAX_REQUEST_LINE_LEN - 1)
          parser->temp_buf[parser->temp_len++] = c;
        else
          return i;
      }
      break;

    case HTTP_PARSER_HEADERS:
      if (c == '\r') {
        parser->temp_buf[parser->temp_len] = '\0';
        if (parser->temp_len == 0) {
          parser->blank_line = 1;
        } else {
          char *colon = strchr(parser->temp_buf, ':');
          if (colon) {
            *colon = '\0';
            char *f = parser->temp_buf;
            char *v = colon + 1;
            while (*v && isspace(*v))
              v++;
            size_t vlen = strlen(v);
            while (vlen > 0 && isspace(v[vlen - 1]))
              v[--vlen] = '\0';
            if (strcasecmp(f, "Content-Length") == 0)
              parser->content_length = (size_t)atol(v);
            if (settings->on_header)
              settings->on_header(parser->user_data, f, v);
          }
          parser->temp_len = 0;
        }
      } else if (c == '\n') {
        if (parser->blank_line) {
          if (settings->on_headers_complete)
            settings->on_headers_complete(parser->user_data);
          parser->state = (parser->content_length == 0) ? HTTP_PARSER_DONE
                                                        : HTTP_PARSER_BODY;
          parser->body_received = 0;
          if (parser->state == HTTP_PARSER_DONE && settings->on_complete)
            settings->on_complete(parser->user_data);
        }
        parser->blank_line = 0;
      } else {
        if (parser->temp_len < MAX_HEADER_LINE_LEN - 1)
          parser->temp_buf[parser->temp_len++] = c;
        else
          return i;
      }
      break;

    case HTTP_PARSER_BODY:
      if (settings->on_body)
        settings->on_body(parser->user_data, &c, 1);
      if (++parser->body_received >= parser->content_length) {
        parser->state = HTTP_PARSER_DONE;
        if (settings->on_complete)
          settings->on_complete(parser->user_data);
      }
      break;

    default:
      break;
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
  if (parser)
    ud = parser->user_data;
  http_parser_init(parser);
  parser->user_data = ud;
}

http_method_t http_method_from_string(const char *method) {
  if (strcmp(method, "GET") == 0)
    return HTTP_METHOD_GET;
  if (strcmp(method, "POST") == 0)
    return HTTP_METHOD_POST;
  if (strcmp(method, "PUT") == 0)
    return HTTP_METHOD_PUT;
  if (strcmp(method, "DELETE") == 0)
    return HTTP_METHOD_DELETE;
  if (strcmp(method, "HEAD") == 0)
    return HTTP_METHOD_HEAD;
  if (strcmp(method, "OPTIONS") == 0)
    return HTTP_METHOD_OPTIONS;
  if (strcmp(method, "PATCH") == 0)
    return HTTP_METHOD_PATCH;
  return HTTP_METHOD_UNKNOWN;
}

const char *http_method_to_string(http_method_t method) {
  switch (method) {
  case HTTP_METHOD_GET:
    return "GET";
  case HTTP_METHOD_POST:
    return "POST";
  case HTTP_METHOD_PUT:
    return "PUT";
  case HTTP_METHOD_DELETE:
    return "DELETE";
  case HTTP_METHOD_HEAD:
    return "HEAD";
  case HTTP_METHOD_OPTIONS:
    return "OPTIONS";
  case HTTP_METHOD_PATCH:
    return "PATCH";
  default:
    return "UNKNOWN";
  }
}

/* HTTP server implementation */
static void on_request_line(void *user_data, http_method_t method,
                            const char *uri, const char *version) {
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
  LOG(LOG_DEBUG, "on_request_line: uri=%s version=%s keep_alive=%d fd=%d",
      conn->uri, version ? version : "(null)", conn->keep_alive, conn->sock);
}

static void on_header(void *user_data, const char *field, const char *value) {
  http_conn_t *conn = (http_conn_t *)user_data;
  if (!conn || !field || !value)
    return;
  if (conn->header_count < MAX_HEADERS) {
    strncpy(conn->headers[conn->header_count].field, field,
            MAX_HEADER_FIELD_LEN - 1);
    conn->headers[conn->header_count].field[MAX_HEADER_FIELD_LEN - 1] = '\0';
    strncpy(conn->headers[conn->header_count].value, value,
            MAX_HEADER_VALUE_LEN - 1);
    conn->headers[conn->header_count].value[MAX_HEADER_VALUE_LEN - 1] = '\0';
    conn->header_count++;
  }
}

static void on_body(void *user_data, const char *data, size_t len) {
  http_conn_t *conn = (http_conn_t *)user_data;
  if (!conn || !data || len == 0)
    return;
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
  snprintf(conn->upload_path, sizeof(conn->upload_path),
           "%s/.upload_%d_%ld.tmp", SERVE_PATH, (int)conn->sock,
           (long)get_time_ms());
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
  if (!conn)
    return;
  conn->expected_content_length = 0;
  conn->body_len = 0;
  /* Look for Content-Length and Connection headers */
  for (size_t i = 0; i < conn->header_count; i++) {
    const char *f = conn->headers[i].field;
    const char *v = conn->headers[i].value;
    if (!f || !v)
      continue;
    /* Case-insensitive compare for header names */
    if (strcasecmp(f, "Content-Length") == 0) {
      conn->expected_content_length = (size_t)atoi(v);
      if (conn->expected_content_length > sizeof(conn->body_buf)) {
        /* Too large for our buffer */
        LOG(LOG_INFO, "Content-Length %zu exceeds buffer, will stream to disk",
            conn->expected_content_length);
        /* prepare upload path but do not open yet until body arrives */
        conn->upload_fp = NULL;
        conn->upload_path[0] = '\0';
      }
    } else if (strcasecmp(f, "Connection") == 0) {
      if (strcasecmp(v, "keep-alive") == 0)
        conn->keep_alive = 1;
      else
        conn->keep_alive = 0;
      LOG(LOG_DEBUG,
          "on_headers_complete: Connection: %s -> keep_alive=%d fd=%d", v,
          conn->keep_alive, conn->sock);
    }
  }
}

static void on_complete(void *user_data) {
  http_conn_t *conn = (http_conn_t *)user_data;
  if (!conn)
    return;
  /* Only call on_request when full body received */
  if (conn->expected_content_length == 0 ||
      conn->body_len >= conn->expected_content_length) {
    if (conn->on_request)
      conn->on_request(conn, conn->method, conn->uri);
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
    setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt,
               sizeof(opt));
#if defined(SO_REUSEPORT)
    setsockopt(server->listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt,
               sizeof(opt));
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
  if (socket_bind(server->listen_sock, (struct sockaddr *)&addr,
                  sizeof(addr)) != 0) {
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
        if (conn->sock > max_fd)
          max_fd = (int)conn->sock;
      }
    }

    struct timeval tv = {1, 0};
    int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      LOG(LOG_WARN, "select failed: %d", get_last_error());
      continue;
    }

    if (FD_ISSET(server->listen_sock, &read_fds)) {
      struct sockaddr_in client_addr;
      socklen_t addr_len = sizeof(client_addr);
      socket_t client_sock = socket_accept(
          server->listen_sock, (struct sockaddr *)&client_addr, &addr_len);
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
        ssize_t n = socket_recv(conn->sock, conn->read_buf + conn->read_len,
                                READ_BUF_SIZE - conn->read_len, 0);
        if (n > 0) {
          conn->read_len += n;
          conn->last_active = get_time_ms();
          size_t parsed =
              http_parser_execute(&conn->parser, &conn->parser_settings,
                                  conn->read_buf, conn->read_len);
          if (parsed < conn->read_len) {
            memmove(conn->read_buf, conn->read_buf + parsed,
                    conn->read_len - parsed);
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
      if (conn->sock != INVALID_SOCKET &&
          (now - conn->last_active) > (CONNECTION_TIMEOUT_SEC * 1000)) {
        LOG(LOG_INFO, "connection timeout (fd=%d)", conn->sock);
        http_conn_close(conn);
        server->conn_count--;
      }
    }
  }
}

void http_server_stop(http_server_t *server) {
  if (!server)
    return;
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

static int http_build_response_headers(char *buf, size_t buf_size,
                                       const char *version, int status,
                                       const char *content_type,
                                       size_t content_length, int keep_alive,
                                       const char *extra_headers) {
  char date[64];
  if (http_format_date(date, sizeof(date), time(NULL)) < 0)
    return -1;
  const char *ctype = content_type ? content_type : "application/octet-stream";
  int hlen = snprintf(
      buf, buf_size,
      "%s %d %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\n", version,
      status, http_status_reason(status), date, HTTP_SERVER_NAME, ctype);
  if (hlen < 0 || hlen >= (int)buf_size)
    return -1;
  size_t remaining = buf_size - (size_t)hlen;
  char *p = buf + hlen;
  int n;
  if (content_length != (size_t)-1) {
    n = snprintf(p, remaining, "Content-Length: %zu\r\n", content_length);
    if (n < 0 || n >= (int)remaining)
      return -1;
    p += n;
    remaining -= n;
    hlen += n;
  }
  n = snprintf(p, remaining, "Connection: %s\r\n",
               keep_alive ? "keep-alive" : "close");
  if (n < 0 || n >= (int)remaining)
    return -1;
  p += n;
  remaining -= n;
  hlen += n;
  if (extra_headers) {
    n = snprintf(p, remaining, "%s", extra_headers);
    if (n < 0 || n >= (int)remaining)
      return -1;
    p += n;
    remaining -= n;
    hlen += n;
  }
  n = snprintf(p, remaining, "\r\n");
  if (n < 0 || n >= (int)remaining)
    return -1;
  hlen += n;
  return hlen;
}

const char *http_status_reason(int status) {
  switch (status) {
  case 200:
    return "OK";
  case 201:
    return "Created";
  case 202:
    return "Accepted";
  case 204:
    return "No Content";
  case 301:
    return "Moved Permanently";
  case 302:
    return "Moved Temporarily";
  case 304:
    return "Not Modified";
  case 400:
    return "Bad Request";
  case 401:
    return "Unauthorized";
  case 403:
    return "Forbidden";
  case 404:
    return "Not Found";
  case 500:
    return "Internal Server Error";
  case 501:
    return "Not Implemented";
  case 502:
    return "Bad Gateway";
  case 503:
    return "Service Unavailable";
  default: {
    int cls = status / 100;
    switch (cls) {
    case 1:
      return "Informational";
    case 2:
      return "Success";
    case 3:
      return "Redirection";
    case 4:
      return "Client Error";
    case 5:
      return "Server Error";
    default:
      return "Unknown";
    }
  }
  }
}

int http_format_date(char *buf, size_t buf_size, time_t t) {
  struct tm tm;
#if PLATFORM_WINDOWS
  if (gmtime_s(&tm, &t) != 0)
    return -1;
#else
  if (gmtime_r(&t, &tm) == NULL)
    return -1;
#endif
  if (strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", &tm) == 0)
    return -1;
  return 0;
}

time_t http_parse_date(const char *str) {
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  char *p;
#if defined(_XOPEN_VERSION) || PLATFORM_LINUX || PLATFORM_MACOS
  p = strptime(str, "%a, %d %b %Y %H:%M:%S GMT", &tm);
  if (p) {
#if PLATFORM_WINDOWS
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
  }
  p = strptime(str, "%A, %d-%b-%y %H:%M:%S GMT", &tm);
  if (p) {
#if PLATFORM_WINDOWS
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
  }
  p = strptime(str, "%a %b %d %H:%M:%S %Y", &tm);
  if (p) {
#if PLATFORM_WINDOWS
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
  }
#endif
  return (time_t)-1;
}

int http_conn_send_response(http_conn_t *conn, int status, const char *body) {
  if (!conn || conn->sock == INVALID_SOCKET)
    return -1;
  char header[WRITE_BUF_SIZE];
  size_t body_len = body ? strlen(body) : 0;
  int hlen = http_build_response_headers(header, sizeof(header), "HTTP/1.0",
                                         status, "text/plain", body_len,
                                         conn->keep_alive, NULL);
  if (hlen < 0 || hlen >= (int)sizeof(header))
    return -1;

  ssize_t sent = socket_send_all(conn->sock, header, (size_t)hlen);
  if (sent != (ssize_t)hlen) {
    LOG(LOG_WARN, "send header failed on fd=%d: %zd/%d", conn->sock, sent,
        hlen);
    http_conn_close(conn);
    return -1;
  }
  /* For HEAD requests, include Content-Length but do not send the body */
  if (conn->method != HTTP_METHOD_HEAD && body_len > 0) {
    sent = socket_send_all(conn->sock, body, body_len);
    if (sent != (ssize_t)body_len) {
      LOG(LOG_WARN, "send body failed on fd=%d: %zd/%zu", conn->sock, sent,
          body_len);
      http_conn_close(conn);
      return -1;
    }
  }

  if (conn->keep_alive) {
    if (conn->read_len > 0) {
      LOG(LOG_INFO, "pipelining detected, closing connection fd=%d",
          conn->sock);
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

void http_server_set_request_handler(http_server_t *server,
                                     void (*handler)(http_conn_t *conn,
                                                     http_method_t method,
                                                     const char *uri)) {
  for (int i = 0; i < MAX_CONNECTIONS; i++) {
    server->connections[i].on_request = handler;
  }
}

/* Socket implementation */
int socket_create(int family, int type, int protocol) {
#if PLATFORM_WINDOWS
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    return INVALID_SOCKET;
#endif
  return socket(family, type, protocol);
}

int socket_bind(socket_t sock, const struct sockaddr *addr, socklen_t addrlen) {
  return bind(sock, addr, addrlen);
}

int socket_listen(socket_t sock, int backlog) { return listen(sock, backlog); }

socket_t socket_accept(socket_t sock, struct sockaddr *addr,
                       socklen_t *addrlen) {
  return accept(sock, addr, addrlen);
}

int socket_connect(socket_t sock, const struct sockaddr *addr,
                   socklen_t addrlen) {
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
    if (n == 0)
      return (ssize_t)total;
    int err = get_last_error();
    if (err == EAGAIN || err == EWOULDBLOCK) {
      fd_set wfds;
      FD_ZERO(&wfds);
      FD_SET(sock, &wfds);
      struct timeval tv = {1, 0};
      int sel = select((int)sock + 1, NULL, &wfds, NULL, &tv);
      if (sel <= 0)
        return -1;
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

char *strerror_platform(int err) { return strerror(err); }

/* File I/O implementation */
int file_exists(const char *path) { return access(path, F_OK) == 0; }

int is_directory(const char *path) {
  struct stat sb;
  if (stat(path, &sb) != 0) {
    return 0;
  }
  return S_ISDIR(sb.st_mode);
}

int file_read(const char *path, file_content_t *content) {
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return -1;
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
  size_t read_size = fread(content->data, 1, (size_t)size, fp);
  if (read_size != (size_t)size) {
    free(content->data);
    fclose(fp);
    return -1;
  }
  content->data[size] = '\0';
  content->size = (size_t)size;
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
  if (!ext)
    return "application/octet-stream";
  ext++;
  if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0)
    return "text/html";
  if (strcmp(ext, "css") == 0)
    return "text/css";
  if (strcmp(ext, "js") == 0)
    return "application/javascript";
  if (strcmp(ext, "json") == 0)
    return "application/json";
  if (strcmp(ext, "xml") == 0)
    return "application/xml";
  if (strcmp(ext, "txt") == 0)
    return "text/plain";
  if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0)
    return "image/jpeg";
  if (strcmp(ext, "png") == 0)
    return "image/png";
  if (strcmp(ext, "gif") == 0)
    return "image/gif";
  if (strcmp(ext, "svg") == 0)
    return "image/svg+xml";
  if (strcmp(ext, "ico") == 0)
    return "image/x-icon";
  return "application/octet-stream";
}

void url_decode(char *dst, const char *src, size_t dst_size) {
  size_t i = 0, j = 0;
  while (src[i] && j < dst_size - 1) {
    if (src[i] == '%' && src[i + 1] && src[i + 2]) {
      char hex[3] = {src[i + 1], src[i + 2], '\0'};
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

int path_normalize(char *dst, const char *src, size_t dst_size) {
  if (dst_size == 0)
    return -1;
  dst[0] = '\0';
  char *parts[32];
  int part_count = 0;
  char tmp[MAX_URI_LEN];
  strncpy(tmp, src, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = '\0';
  char *token = strtok(tmp, "/\\");
  while (token && part_count < 32) {
    if (strcmp(token, ".") == 0) {
    } else if (strcmp(token, "..") == 0) {
      if (part_count > 0)
        part_count--;
    } else
      parts[part_count++] = token;
    token = strtok(NULL, "/\\");
  }
  dst[0] = '\0';
  for (int i = 0; i < part_count; i++) {
    if (strlen(dst) + strlen(parts[i]) + 2 <= dst_size) {
      strcat(dst, "/");
      strcat(dst, parts[i]);
    }
  }
  if (dst[0] == '\0')
    strncpy(dst, "/", dst_size - 1);
  return 0;
}

int path_is_safe(const char *path) {
  if (!path)
    return 0;
  if (path[0] == '/' || strchr(path, '\\') != NULL)
    return 0;
  if (strstr(path, "..") != NULL)
    return 0;
  if (strlen(path) >= 3 && path[1] == ':' &&
      (path[2] == '/' || path[2] == '\\'))
    return 0;
  return 1;
}

int http_conn_send_file(http_conn_t *conn, int status, const char *path) {
  file_content_t content;
  if (file_read(path, &content) != 0)
    return http_conn_send_response(conn, 404, "File not found");
  const char *mime = mime_type_from_path(path);
  char resp[WRITE_BUF_SIZE];
  int hlen =
      http_build_response_headers(resp, sizeof(resp), "HTTP/1.0", status, mime,
                                  content.size, conn->keep_alive, NULL);
  if (hlen < 0 || hlen >= (int)sizeof(resp)) {
    file_free(&content);
    return -1;
  }
  if (socket_send_all(conn->sock, resp, (size_t)hlen) != (ssize_t)hlen) {
    file_free(&content);
    http_conn_close(conn);
    return -1;
  }
  /* For HEAD requests, do not send the entity body */
  if (conn->method != HTTP_METHOD_HEAD) {
    if (socket_send_all(conn->sock, content.data, content.size) !=
        (ssize_t)content.size) {
      file_free(&content);
      http_conn_close(conn);
      return -1;
    }
  }
  file_free(&content);
  if (conn->keep_alive) {
    conn->header_count = 0;
    conn->body_len = 0;
    http_parser_reset(&conn->parser);
    return 0;
  }
  http_conn_close(conn);
  return 0;
}

int http_conn_send_directory_listing(http_conn_t *conn, const char *path,
                                     const char *uri_path) {
  DIR *dir = opendir(path);
  if (!dir)
    return http_conn_send_response(conn, 403, "Forbidden");

  // Send Chunked Header
  http_conn_start_chunked_response(conn, 200, "text/html");

  // styles and scripts
  const char *head =
      "<!DOCTYPE html><html><head>"
      "<title>System Loading...</title>"
      "<script "
      "src=\"https://cdnjs.cloudflare.com/ajax/libs/matter-js/0.19.0/"
      "matter.min.js\"></script>"
      "<style>"
      "body { font-family: 'Consolas', 'Monaco', 'Courier New', monospace; "
      "background: #000; color: #0f0; overflow: hidden; margin: 0; padding: 0; "
      "}"
      "canvas#matrix-bg { position: fixed; top: 0; left: 0; z-index: 0; "
      "opacity: 0.8; }"
      "h1 { position: absolute; top: 20px; width: 100%; text-align: center; "
      "z-index: 1; color: #fff; text-shadow: 0 0 10px #0f0, 0 0 20px #0f0; "
      "letter-spacing: 5px; background: rgba(0,0,0,0.7); padding: 10px 0; "
      "backdrop-filter: blur(2px); }"
      ".file-container { position: relative; width: 100vw; height: 100vh; "
      "overflow: hidden; z-index: 10; pointer-events: none; }"
      ".file-item { position: absolute; top: 0; left: 0; width: 400px; "
      "max-width: 90vw; background: rgba(0, 20, 0, 0.9); border: 1px solid "
      "#0f0; border-radius: 2px; padding: 10px 15px; cursor: pointer; "
      "user-select: none; "
      "box-shadow: 0 0 5px #0f0, inset 0 0 10px rgba(0, 255, 0, 0.2); "
      "white-space: nowrap; font-size: 14px; z-index: 20; display: flex; "
      "flex-direction: column; align-items: center; justify-content: center; "
      "min-width: 120px; color: #fff; pointer-events: auto; }"
      ".file-item:hover { background: #0f0; color: #000; box-shadow: 0 0 20px "
      "#0f0; }"
      ".file-info { font-size: 10px; color: #8f8; margin-top: 5px; "
      "text-transform: uppercase; }"
      ".dir { border-color: #fff; box-shadow: 0 0 5px #fff; color: #fff; }"
      "a { color: inherit; text-decoration: none; display: flex; "
      "flex-direction: column; align-items: center; width: 100%; height: 100%; "
      "}"
      "</style></head><body>"
      "<canvas id=\"matrix-bg\"></canvas>"
      "<h1>SYSTEM ROOT // ";

  http_conn_send_chunk(conn, head, strlen(head));
  http_conn_send_chunk(conn, uri_path, strlen(uri_path));
  http_conn_send_chunk(
      conn, "</h1><div id=\"canvas-container\" class=\"file-container\">", 51);

  struct dirent *ent;
  char buf[4096];
  char full_path[1024];
  struct stat st;

  // Pass 1: Directories
  while ((ent = readdir(dir))) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    snprintf(full_path, sizeof(full_path), "%s/%s", path, ent->d_name);
    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
      // Send Directory Entry
      struct tm *tm_info = localtime(&st.st_mtime);
      char date_str[64];
      strftime(date_str, sizeof(date_str), "%H:%M:%S", tm_info);
      int len = snprintf(buf, sizeof(buf),
                         "<div class=\"file-item dir\">"
                         "<a href=\"%s%s%s\">"
                         "<div>[%s]</div>"
                         "<div class=\"file-info\">DIR :: %s</div>"
                         "</a></div>",
                         (strcmp(uri_path, "/") == 0) ? "" : uri_path,
                         (strcmp(uri_path, "/") == 0) ? "" : "/", ent->d_name,
                         ent->d_name, date_str);
      if (len > 0)
        http_conn_send_chunk(conn, buf, len);
    }
  }

  rewinddir(dir);

  // Pass 2: Files
  while ((ent = readdir(dir))) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    snprintf(full_path, sizeof(full_path), "%s/%s", path, ent->d_name);
    if (stat(full_path, &st) == 0 && !S_ISDIR(st.st_mode)) {
      // Send File Entry
      char size_str[32];
      if (st.st_size < 1024)
        snprintf(size_str, sizeof(size_str), "%ld B", (long)st.st_size);
      else if (st.st_size < 1024 * 1024)
        snprintf(size_str, sizeof(size_str), "%.1f KB", st.st_size / 1024.0);
      else
        snprintf(size_str, sizeof(size_str), "%.1f MB",
                 st.st_size / (1024.0 * 1024.0));

      struct tm *tm_info = localtime(&st.st_mtime);
      char date_str[64];
      strftime(date_str, sizeof(date_str), "%H:%M:%S", tm_info);

      int len = snprintf(buf, sizeof(buf),
                         "<div class=\"file-item\">"
                         "<a href=\"%s%s%s\">"
                         "<div>%s</div>"
                         "<div class=\"file-info\">%s :: %s</div>"
                         "</a></div>",
                         (strcmp(uri_path, "/") == 0) ? "" : uri_path,
                         (strcmp(uri_path, "/") == 0) ? "" : "/", ent->d_name,
                         ent->d_name, size_str, date_str);
      if (len > 0)
        http_conn_send_chunk(conn, buf, len);
    }
  }

  closedir(dir);

  // Send Matrix Rain + Physics JS
  const char *footer =
      "</div>"
      "<script>"
      "// Matrix Background\n"
      "var c = document.getElementById('matrix-bg');\n"
      "var ctx = c.getContext('2d');\n"
      "c.width = window.innerWidth;\n"
      "c.height = window.innerHeight;\n"
      "\n"
      "var chars = '0123456789ABCDEF';\n" // Hex characters
      "chars = chars.split('');\n"
      "var font_size = 14;\n"
      "var columns = c.width/font_size;\n"
      "var drops = [];\n"
      "for(var x=0; x<columns; x++) drops[x] = 1;\n"
      "\n"
      "function drawMatrix() {\n"
      "    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';\n" // Fade effect
      "    ctx.fillRect(0, 0, c.width, c.height);\n"
      "    ctx.fillStyle = '#0F0';\n"
      "    ctx.font = font_size + 'px arial';\n"
      "    for(var i=0; i<drops.length; i++){\n"
      "        var text = chars[Math.floor(Math.random()*chars.length)];\n"
      "        ctx.fillText(text, i*font_size, drops[i]*font_size);\n"
      "        if(drops[i]*font_size > c.height && Math.random() > 0.975)\n"
      "            drops[i] = 0;\n"
      "        drops[i]++;\n"
      "    }\n"
      "}\n"
      "setInterval(drawMatrix, 33);\n"
      "\n"
      "// Physics Engine\n"
      "window.onload = function() {\n"
      "    if (typeof Matter === 'undefined') { alert('Matrix connection "
      "failed.'); return; }\n"
      "    var Engine = Matter.Engine,\n"
      "        Bodies = Matter.Bodies,\n"
      "        Composite = Matter.Composite,\n"
      "        Mouse = Matter.Mouse,\n"
      "        MouseConstraint = Matter.MouseConstraint;\n"
      "\n"
      "    var engine = Engine.create();\n"
      "    // Default gravity enabled for falling stream\n"
      "    engine.world.gravity.y = 0.5;\n" // Low gravity for "floaty" feel
      "    \n"
      "    var container = document.getElementById('canvas-container');\n"
      "    var width = window.innerWidth;\n"
      "    var height = window.innerHeight;\n"
      "\n"
      "    // Floor only - let them pile up\n"
      "    var ground = Bodies.rectangle(width/2, height + 30, width, 60, { "
      "isStatic: true });\n"
      "    var leftWall = Bodies.rectangle(-30, height/2, 60, height * 10, { "
      "isStatic: true });\n"
      "    var rightWall = Bodies.rectangle(width+30, height/2, 60, height * "
      "10, { isStatic: true });\n"
      "    Composite.add(engine.world, [ground, leftWall, rightWall]);\n"
      "\n"
      "    var items = document.querySelectorAll('.file-item');\n"
      "    var colWidth = 420; // Width + margin\n"
      "    var itemHeight = 80; // Approx height per item including margin\n"
      "    var maxPerCol = Math.floor((height - 200) / itemHeight); // Leave "
      "space for title/floor\n"
      "    if (maxPerCol < 5) maxPerCol = 5; // Minimum items per col\n"
      "    \n"
      "    // Calculate required columns\n"
      "    var totalItems = items.length;\n"
      "    var reqCols = Math.ceil(totalItems / maxPerCol);\n"
      "    var totalGridWidth = reqCols * colWidth;\n"
      "    var startXBase = (width - totalGridWidth) / 2;\n"
      "    if (startXBase < 50) startXBase = 50; // Min left margin\n"
      "\n"
      "    items.forEach(function(item, index) {\n"
      "        // Determine column based on index\n"
      "        var col = Math.floor(index / maxPerCol);\n"
      "        var row = index % maxPerCol;\n"
      "        \n"
      "        var startX = startXBase + (col * colWidth) + (colWidth / 2);\n"
      "        \n"
      "        // Randomize fall start time\n"
      "        var baseDelay = row * 200;\n"
      "        var randomDelay = Math.random() * 500;\n"
      "        // Start high up\n"
      "        var startY = -200 - baseDelay - randomDelay;\n"
      "\n"
      "        var w = item.offsetWidth;\n"
      "        var h = item.offsetHeight;\n"
      "\n"
      "        var body = Bodies.rectangle(startX, startY, w, h, {\n"
      "            restitution: 0.2,\n"
      "            friction: 0.8,\n"
      "            density: 0.05\n"
      "        });\n"
      "        \n"
      "        // Update DOM transform loop\n"
      "        (function update() {\n"
      "             window.requestAnimationFrame(update);\n"
      "             var x = body.position.x - w/2;\n"
      "             var y = body.position.y - h/2;\n"
      "             item.style.transform = 'translate(' + x + 'px, ' + y + "
      "'px) rotate(' + body.angle + 'rad)';\n"
      "        })();\n"
      "        \n"
      "        Composite.add(engine.world, body);\n"
      "    });\n"
      "\n"
      "    var mouse = Mouse.create(document.body);\n"
      "    var mouseConstraint = MouseConstraint.create(engine, {\n"
      "        mouse: mouse,\n"
      "        constraint: { stiffness: 0.2, render: { visible: false } }\n"
      "    });\n"
      "    Composite.add(engine.world, mouseConstraint);\n"
      "    mouse.element.removeEventListener(\"mousewheel\", "
      "mouse.mousewheel);\n"
      "    mouse.element.removeEventListener(\"DOMMouseScroll\", "
      "mouse.mousewheel);\n"
      "\n"
      "    // Run engine\n"
      "    (function run() {\n"
      "        window.requestAnimationFrame(run);\n"
      "        Engine.update(engine, 1000 / 60);\n"
      "    })();\n"
      "\n"
      "    window.addEventListener('resize', function() {\n"
      "         // Simple reload to reset matrix\n"
      "         location.reload();\n"
      "    });\n"
      "};\n"
      "</script>"
      "</body></html>";

  http_conn_send_chunk(conn, footer, strlen(footer));
  http_conn_end_chunked_response(conn);
  return 0;
}

int http_conn_start_chunked_response(http_conn_t *conn, int status,
                                     const char *content_type) {
  char h[WRITE_BUF_SIZE];
  int hlen = http_build_response_headers(
      h, sizeof(h), "HTTP/1.1", status, content_type, (size_t)-1,
      conn->keep_alive, "Transfer-Encoding: chunked\r\n");
  if (hlen < 0 || hlen >= (int)sizeof(h))
    return -1;
  if (socket_send_all(conn->sock, h, (size_t)hlen) != (ssize_t)hlen) {
    http_conn_close(conn);
    return -1;
  }
  return 0;
}

int http_conn_send_chunk(http_conn_t *conn, const char *data, size_t len) {
  char ch[32];
  int clen = snprintf(ch, sizeof(ch), "%zX\r\n", len);
  socket_send_all(conn->sock, ch, (size_t)clen);
  socket_send_all(conn->sock, data, len);
  socket_send_all(conn->sock, "\r\n", 2);
  return 0;
}

int http_conn_end_chunked_response(http_conn_t *conn) {
  socket_send_all(conn->sock, "0\r\n\r\n", 5);
  if (conn->keep_alive)
    http_parser_reset(&conn->parser);
  return 0;
}

int http_conn_send_error(http_conn_t *conn, int status, const char *msg) {
  char body[1024];
  snprintf(body, sizeof(body), "Error %d: %s\n", status, msg);
  return http_conn_send_response(conn, status, body);
}

int http_conn_send_redirect(http_conn_t *conn, int status,
                            const char *location) {
  char headers[MAX_HEADER_FIELD_LEN + MAX_HEADER_VALUE_LEN];
  snprintf(headers, sizeof(headers), "Location: %s\r\n", location);

  char response[WRITE_BUF_SIZE];
  int hlen =
      http_build_response_headers(response, sizeof(response), "HTTP/1.1",
                                  status, NULL, 0, conn->keep_alive, headers);
  if (hlen > 0 && hlen < (int)sizeof(response)) {
    socket_send_all(conn->sock, response, (size_t)hlen);
  }

  if (conn->keep_alive) {
    conn->header_count = 0;
    conn->body_len = 0;
    http_parser_reset(&conn->parser);
    return 0;
  }
  http_conn_close(conn);
  return 0;
}

#endif /* HTTP_H */
