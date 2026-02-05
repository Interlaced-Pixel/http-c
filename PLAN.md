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

## Remaining Steps
7. Add robustness features (timeouts, error handling, logging)
8. Write unit tests (parser and server tests)
9. Optimize for production (chunked encoding, buffer pooling)
10. Add TLS support (mbedTLS integration)
11. Documentation and build (README, CMake, LICENSE)

## Verification
- Unit tests: `make test` passes all tests
- Integration: `curl http://localhost:8080/hello` returns "Hello HTTP!"
- Stress: `ab -n 1000 -c 8` handles load without memory leaks
- Cross-platform: Builds on Linux/macOS/Windows
- Memory: <600KB RAM for 8 connections

## Decisions
- Event-driven single-threaded: 10-100x RAM savings vs threads
- HTTP/1.0 + Keep-Alive MVP: 95% embedded value, minimal complexity
- Static pools: Eliminates fragmentation, compile-time config
- Callback parser: Streaming design keeps memory constant
- Makefile primary: Dependency-free for embedded