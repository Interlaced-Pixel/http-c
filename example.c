#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#define HTTP_IMPLEMENTATION
#include "http.h"
#include <signal.h>

static void request_handler(http_conn_t *conn, http_method_t method,
                            const char *uri) {
  (void)method;

  // Decode URL
  char decoded_uri[MAX_URI_LEN];
  url_decode(decoded_uri, uri, sizeof(decoded_uri));

  // Normalize path to prevent traversal
  char normalized_path[MAX_URI_LEN];
  if (path_normalize(normalized_path, decoded_uri, sizeof(normalized_path)) !=
      0) {
    http_conn_send_error(conn, 403, "Forbidden or path normalization failed");
    return;
  }

  LOG(LOG_INFO, "Request: %s -> %s", uri, normalized_path);

  // Convert to relative path for our server root
  const char *p = normalized_path;
  while (*p == '/')
    p++;

  char rel_path[MAX_URI_LEN];
  if (*p == '\0') {
    strcpy(rel_path, ".");
  } else {
    strncpy(rel_path, p, sizeof(rel_path) - 1);
    rel_path[sizeof(rel_path) - 1] = '\0';
  }

  if (method == HTTP_METHOD_PUT) {
    if (!path_is_safe(rel_path)) {
      http_conn_send_error(conn, 403, "Forbidden");
      return;
    }
    FILE *fp = fopen(rel_path, "wb");
    if (!fp) {
      http_conn_send_error(conn, 500, "Internal Server Error");
      return;
    }
    fwrite(conn->body_buf, 1, conn->body_len, fp);
    fclose(fp);
    http_conn_send_response(conn, 201, "Created");
    return;
  }

  if (method == HTTP_METHOD_DELETE) {
    if (!path_is_safe(rel_path)) {
      http_conn_send_error(conn, 403, "Forbidden");
      return;
    }
    if (remove(rel_path) == 0) {
      http_conn_send_response(conn, 200, "Deleted");
    } else {
      http_conn_send_error(conn, 404, "Not Found");
    }
    return;
  }

  if (is_directory(rel_path)) {
    // Redirect if missing trailing slash
    size_t uri_len = strlen(uri);
    if (uri_len > 0 && uri[uri_len - 1] != '/') {
      char redir[MAX_URI_LEN];
      snprintf(redir, sizeof(redir), "%s/", uri);
      http_conn_send_redirect(conn, 301, redir);
      return;
    }

    char index_path[MAX_URI_LEN];
    snprintf(index_path, sizeof(index_path), "%s/index.html", rel_path);

    if (file_exists(index_path)) {
      http_conn_send_file(conn, 200, index_path);
    } else {
#if DIRECTORY_LISTING
      http_conn_send_directory_listing(conn, rel_path, uri);
#else
      http_conn_send_error(conn, 404, "Not Found");
#endif
    }
    return;
  }

  if (path_is_safe(rel_path) && file_exists(rel_path)) {
    http_conn_send_file(conn, 200, rel_path);
  } else if (strcmp(decoded_uri, "/chunked") == 0) {
    http_conn_start_chunked_response(conn, 200, "text/plain");
    http_conn_send_chunk(conn, "Chunk 1\n", 8);
    http_conn_send_chunk(conn, "Chunk 2\n", 8);
    http_conn_send_chunk(conn, "Chunk 3\n", 8);
    http_conn_end_chunked_response(conn);
  } else {
    http_conn_send_error(conn, 404, "Not Found");
  }
}

static http_server_t global_server;

static void sigint_handler(int sig) {
  (void)sig;
  LOG(LOG_INFO, "SIGINT received, stopping server");
  http_server_stop(&global_server);
}

int main(int argc, char *argv[]) {
  http_server_t *server = &global_server;
  int port = BIND_PORT;

  if (argc > 1) {
    port = atoi(argv[1]);
  }

  fprintf(stderr, "Initializing server on %s:%d, serving from: %s\n", BIND_IP,
          port, SERVE_PATH);

  if (http_server_init(server, BIND_IP, port) != 0) {
    fprintf(stderr, "Failed to init server\n");
    return 1;
  }

  http_server_set_request_handler(server, request_handler);

  fprintf(stderr, "Server listening on %s:%d\n", BIND_IP, port);
  fprintf(stderr, "Serving from: %s\n", SERVE_PATH);

  signal(SIGINT, sigint_handler);

  http_server_run(server);

  http_server_close(server);
  fprintf(stderr, "Server stopped\n");
  return 0;
}