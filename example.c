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
    http_conn_send_response(conn, 403, "Not found or access denied");
    return;
  }

  LOG(LOG_INFO, "Request: %s -> %s", uri, normalized_path);

  // Convert to relative path for our server root
  const char *rel_path = normalized_path;
  while (*rel_path == '/')
    rel_path++;
  if (*rel_path == '\0')
    rel_path = "index.html";

  if (path_is_safe(rel_path) && file_exists(rel_path)) {
    http_conn_send_file(conn, 200, rel_path);
  } else if (strcmp(decoded_uri, "/chunked") == 0) {
    http_conn_start_chunked_response(conn, 200, "text/plain");
    http_conn_send_chunk(conn, "Chunk 1\n", 8);
    http_conn_send_chunk(conn, "Chunk 2\n", 8);
    http_conn_send_chunk(conn, "Chunk 3\n", 8);
    http_conn_end_chunked_response(conn);
  } else {
    http_conn_send_response(conn, 404, "Not found or access denied");
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