#define HTTP_IMPLEMENTATION
#include "http.h"
#include <signal.h>

static void request_handler(http_conn_t *conn, http_method_t method, const char *uri) {
    (void)method;
    printf("URI: %s\n", uri);
    
    // Decode URL
    char decoded_uri[256];
    url_decode(decoded_uri, uri, sizeof(decoded_uri));
    printf("Decoded: %s\n", decoded_uri);
    
    if (strcmp(decoded_uri, "/") == 0 && file_exists("index.html")) {
        http_conn_send_file(conn, 200, "index.html");
    } else {
        http_conn_send_response(conn, 404, "Not found");
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

    fprintf(stderr, "Initializing server on %s:%d, serving from: %s\n", BIND_IP, port, SERVE_PATH);

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