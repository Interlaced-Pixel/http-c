#include "doctest.h"
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include "http.h"
}

static int handler_called = 0;
static http_server_t *g_server = nullptr;

static void stop_handler(http_conn_t *conn, http_method_t method,
                         const char *uri) {
  (void)method;
  (void)uri;
  handler_called++;
  http_conn_send_response(conn, 200, "stopping");
  if (g_server)
    http_server_stop(g_server);
}

static void passive_handler(http_conn_t *conn, http_method_t method,
                            const char *uri) {
  (void)conn;
  (void)method;
  (void)uri;
  handler_called++;
}

static void *server_thread_func(void *arg) {
  http_server_t *server = (http_server_t *)arg;
  http_server_run(server);
  return nullptr;
}

TEST_SUITE("Server") {
  TEST_CASE("integration and callbacks") {
    // Utilities & Mem Pool
    char *dup = strdup_safe("test");
    CHECK_EQ(std::string(dup), "test");
    free(dup);
    mem_pool_t pool;
    mem_pool_init(&pool, 5);
    void *p1 = mem_pool_alloc(&pool);
    CHECK(p1 != nullptr);
    mem_pool_free(&pool, p1);

    // Methods & MIME
    CHECK_EQ(http_method_from_string("PATCH"), HTTP_METHOD_PATCH);
    CHECK_EQ(std::string(http_method_to_string(HTTP_METHOD_PATCH)), "PATCH");

    // File I/O
    file_content_t fc;
    FILE *ft = fopen("t.txt", "w");
    fputc('x', ft);
    fclose(ft);
    CHECK_EQ(file_read("t.txt", &fc), 0);
    file_free(&fc);

    // Server Logic & Threaded Integration
    http_server_t server;
    if (http_server_init(&server, "127.0.0.1", 0) == 0) {
      struct sockaddr_in sin;
      socklen_t slen = sizeof(sin);
      getsockname(server.listen_sock, (struct sockaddr *)&sin, &slen);
      int port = ntohs(sin.sin_port);
      g_server = &server;
      http_server_set_request_handler(&server, stop_handler);
      pthread_t tid;
      pthread_create(&tid, nullptr, server_thread_func, &server);

      struct sockaddr_in srv_addr;
      srv_addr.sin_family = AF_INET;
      srv_addr.sin_port = htons(port);
      inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

      int socks[MAX_CONNECTIONS];
      for (int i = 0; i < 5; i++) {
        socks[i] = socket(AF_INET, SOCK_STREAM, 0);
        connect(socks[i], (struct sockaddr *)&srv_addr, sizeof(srv_addr));
      }

      // Normal Req with pipelining
      const char *preq = "GET /p HTTP/1.1\r\n\r\nGET /p HTTP/1.1\r\n\r\n";
      send(socks[0], preq, strlen(preq), 0);

      // Server stop
      int ss = socket(AF_INET, SOCK_STREAM, 0);
      connect(ss, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
      const char *st = "GET /s HTTP/1.1\r\n\r\n";
      send(ss, st, strlen(st), 0);

      pthread_join(tid, nullptr);
      for (int i = 0; i < 5; i++)
        close(socks[i]);
      close(ss);
      http_server_close(&server);
      g_server = nullptr;
    }
    unlink("t.txt");

    // Direct Callback Testing
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
      http_conn_t conn;
      http_conn_init(&conn);
      conn.sock = sv[0];
      handler_called = 0;
      conn.on_request = passive_handler;

      // Body spill
      size_t lb_size = 4096 + 100;
      char *lb = (char *)malloc(lb_size + 200);
      int hlen = sprintf(lb, "POST /l HTTP/1.1\r\nContent-Length: %zu\r\n\r\n",
                         lb_size);
      memset(lb + hlen, 'A', lb_size);
      http_parser_execute(&conn.parser, &conn.parser_settings, lb,
                          hlen + lb_size);
      CHECK_EQ(handler_called, 1);
      if (conn.upload_fp)
        fclose(conn.upload_fp);
      unlink(conn.upload_path);
      free(lb);

      http_conn_send_response(&conn, 404, "Not Found");
      http_conn_send_file(&conn, 200, "nonexistent.file");
      http_conn_start_chunked_response(&conn, 200, "text/plain");
      http_conn_send_chunk(&conn, "hi", 2);
      http_conn_end_chunked_response(&conn);
      http_conn_send_directory_listing(&conn, ".", "/");

      // HEAD method test: create a small file and ensure headers are sent but no body
      FILE *hf = fopen("head_test.txt", "w");
      fputs("ABCDEF", hf);
      fclose(hf);
      handler_called = 0;
      conn.method = HTTP_METHOD_HEAD;
      conn.keep_alive = 0;
      // send file via HEAD
      http_conn_send_file(&conn, 200, "head_test.txt");
      // read response from peer
      char buf[1024];
      ssize_t r = read(sv[1], buf, sizeof(buf));
      CHECK(r > 0);
      std::string resp(buf, buf + (size_t)r);
      CHECK(resp.find("Content-Length: 6") != std::string::npos);
      // After headers, there should be no body data
      CHECK(resp.find("\r\n\r\n") != std::string::npos);
      size_t hdr_end = resp.find("\r\n\r\n") + 4;
      CHECK_EQ(resp.size(), hdr_end);
      unlink("head_test.txt");

      close(sv[1]);
      http_conn_close(&conn);
    }
  }
}
