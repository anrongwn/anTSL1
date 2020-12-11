// antsl_client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "pch.h"
#include "uv_tls.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "libuv.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define DEFAULT_PORT 9555

////全局 color stdout
//const char *AN_STDOUT_COLOR_NAME = "console";
//std::shared_ptr<spdlog::logger> g_console = spdlog::stdout_color_mt(AN_STDOUT_COLOR_NAME);


void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
	buf->base = (char*)malloc(size);
	memset(buf->base, 0, size);
	buf->len = size;
	assert(buf->base != NULL && "Memory allocation failed");
}

void echo_read(uv_tls_t *server, int nread, uv_buf_t *buf) {
	fprintf(stderr, "Entering %s\n", __FUNCTION__);

	if (nread == -1) {
		fprintf(stderr, "error echo_read");
		return;
	}

	fprintf(stderr, "%s\n", buf->base);
}

void on_write(uv_write_t *req, int status)
{
	if (status) {
		return;
	}

	uv_tls_read((uv_tls_t*)req->handle->data, alloc_cb, echo_read);
	free(req);
	req = 0;
}

void on_close(uv_tls_t* h)
{
	free(h);
	h = 0;
}




//TEST CODE for the lib
const char * hello = "Hello from lib-tls";
void on_connect(uv_connect_t *req, int status)
{
	fprintf(stderr, "Entering tls_connect callback\n");
	if (status) {
		fprintf(stderr, "TCP connection error\n");
		return;
	}
	fprintf(stderr, "TCP connection established\n");

	uv_tls_t *clnt = (uv_tls_t*)req->handle->data;
	uv_write_t *rq = (uv_write_t*)malloc(sizeof(*rq));
	uv_buf_t dcrypted;

	size_t len = strlen(hello) + 1;
	dcrypted.base = (char *)malloc(len);
	memcpy(dcrypted.base, hello, len);
	dcrypted.len = len;
	assert(rq != 0);
	uv_tls_write(rq, clnt, &dcrypted, on_write);
}


int main(int argc, char *argv[])
{
	std::cout << "Hello antsl_client..." << std::endl;

	
	uv_loop_t *loop = uv_default_loop();

	uv_tls_t *client = (uv_tls_t*)malloc(sizeof *client);
	if (uv_tls_init(loop, client) < 0) {
		free(client);
		client = 0;
		fprintf(stderr, "TLS setup error\n");
		return  -1;
	}

	const int port = DEFAULT_PORT;
	struct sockaddr_in conn_addr;
	int r = uv_ip4_addr("192.168.128.59", port, &conn_addr);
	assert(!r);

	uv_connect_t req = { 0x00 };
	uv_tls_connect(&req, client, (const struct sockaddr*)&conn_addr, on_connect);

	uv_run(loop, UV_RUN_DEFAULT);

	uv_loop_close(loop);
	tls_engine_stop();
	free(client);
	client = 0;


	return 0;

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
