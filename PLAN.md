# HTTP-C Server Implementation Plan

## Overview
This document outlines the production-ready plan for building a high-performance HTTP web server in C for low-memory embedded systems.

## TL;DR
Build a memory-efficient HTTP server using event-driven architecture, streaming HTTP/1.0 parser with Keep-Alive, static memory pools, and portable platform abstractions. Target <100KB binary, 350-600KB RAM for 8 connections. Use Makefile for builds, CMake optional.

## Steps Completed
1. ✅ Set up project structure (include/, src/, lib/, tests/, examples/, plan/)
2. ✅ Implement HTTP parser core (streaming callback-based state machine)
3. ✅ Build event loop and connection manager (single-threaded with select)
4. ✅ Add platform socket abstractions (POSIX/Windows support)
5. ✅ Implement memory management (static pools)
6. ✅ Create demo application (simple_server with GET /hello support)
7. ✅ Full header parsing added (Content-Length, Connection)
8. ✅ POST/PUT upload streaming (in-memory buffer with spill-to-disk temp files)
9. ✅ Keep-Alive / persistent connections implemented and hardened (send-all, pipelining protection, SIGPIPE handling)
10. ✅ Security hardening: path normalization and traversal protection implemented
11. ✅ Reverted logging level to LOG_INFO for production stability
12. ✅ Chunked Transfer Encoding implemented and verified

## Remaining Steps
13. Implement Range requests
14. Security hardening: rate limiting and additional header validation
15. Performance tuning: buffer pooling and memory tuning
16. TLS support (mbedTLS integration)
17. Further testing: add automated tests for uploads and file serving flows
18. Docs, examples, and release packaging

## Verification
- Unit tests: `./tests/keepalive_test.sh` verifies keep-alive; `./tests/security_test.sh` verifies traversal protection.
- Integration: `curl http://localhost:8080/` serves `index.html` and file listing.
- Uploads: large POSTs stream to temp file under `SERVE_PATH`.
- Cross-platform: Builds on macOS and Linux (POSIX).
- Memory: target remains <600KB RAM for 8 connections.

## Decisions
- Event-driven single-threaded: 10-100x RAM savings vs threads
- HTTP/1.0 + Keep-Alive MVP: 95% embedded value, minimal complexity
- Static pools: Eliminates fragmentation, compile-time config
- Callback parser: Streaming design keeps memory constant
- Makefile primary: Dependency-free for embedded

## Notes & Next Actions
- Chunked Transfer: Implemented new API and verified with tests.
- Security: Path normalization implemented in `http.h` and used in `example.c`.
- Recommended next immediate tasks:
	- Implement Range requests for large file streaming/resume support.
	- Add more unit tests for parser edge cases (header overflow, malformed request lines).