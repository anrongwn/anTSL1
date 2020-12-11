#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libuv/uv.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

#include "spdlog/fmt/fmt.h"


#define DEFAULT_PORT 9555
#define DEFAULT_BACKLOG 128

uv_loop_t * g_loop = nullptr; 
uv_tcp_t g_server = { 0x00 };
static struct sockaddr_in g_addr = { 0x00 };

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req) {
	write_req_t *wr = (write_req_t*)req;
	free(wr->buf.base);
	free(wr);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}

void on_close(uv_handle_t* handle) {
	free(handle);
}

void echo_write(uv_write_t *req, int status) {
	if (status) {
		fprintf(stderr, "Write error %s\n", uv_strerror(status));
	}
	free_write_req(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	if (nread > 0) {
		write_req_t *req = (write_req_t*)malloc(sizeof(write_req_t));
		req->buf = uv_buf_init(buf->base, nread);
		uv_write((uv_write_t*)req, client, &req->buf, 1, echo_write);
		return;
	}
	if (nread < 0) {
		if (nread != UV_EOF)
			fprintf(stderr, "Read error %s\n", uv_err_name(nread));
		uv_close((uv_handle_t*)client, on_close);
	}

	free(buf->base);
}

void on_new_connection(uv_stream_t *server, int status) {
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		// error!
		return;
	}

	uv_tcp_t *client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(g_loop, client);
	if (uv_accept(server, (uv_stream_t*)client) == 0) {


		uv_read_start((uv_stream_t*)client, alloc_buffer, echo_read);
	}
	else {
		uv_close((uv_handle_t*)client, on_close);
	}
}


int an_tcp_server_start() {
	if (nullptr == g_loop) return -1;

	int rc = 0;

	rc = uv_tcp_init(g_loop, &g_server);
	rc = uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &g_addr);

	rc = uv_tcp_bind(&g_server, (const sockaddr *)&g_addr, 0);
	rc = uv_listen((uv_stream_t *)&g_server, DEFAULT_BACKLOG, on_new_connection);
	if (rc) {
		fprintf(stderr, "Listen error %s\n", uv_strerror(rc));
		return -1;
	}

	return rc;
}