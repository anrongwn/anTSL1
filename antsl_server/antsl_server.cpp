// antsl_server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC    
#include <stdlib.h>    
#include <crtdbg.h>
#endif 

#include <iostream>
#include <string>
#include <atomic>

#include "pch.h"
#include "uv_tcp_server.h"
#include "uv_tls.h"

#ifdef _DEBUG
#ifndef DBG_NEW
#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
#define new DBG_NEW
#endif 
#endif  // _DEBUG



//External libraries
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "libuv.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define SSL_CHK_ERR(err, s) if((err) == -1) { perror(s); return -1; }
#define SSL_CHK_RV(rv, s) if((rv) != 1) { printf("%s error\n", s); return -1; }
#define SSL_CHK_NULL(x, s) if((x) == nullptr) { printf("%s error\n", s); return -1; }
#define SSL_CHK_SSL(err, s) if((err) == -1) { ERR_print_errors_fp(stderr);  return -1;}


static std::atomic_bool g_exit_flag = false;

////全局 color stdout
//const char *AN_STDOUT_COLOR_NAME = "console";
//std::shared_ptr<spdlog::logger> anlog::getlogger() = spdlog::stdout_color_mt(AN_STDOUT_COLOR_NAME);

//certs 
#define AN_CERTCA "D:/myStudy/anTSL1/deps/openssl-102d_x86/bin/certs/an_ca.crt"
#define AN_CERTSERVER "D:/myStudy/anTSL1/deps/openssl-102d_x86/bin/certs/an_server.crt"
#define AN_KEYSERVER "D:/myStudy/anTSL1/deps/openssl-102d_x86/bin/certs/an_server.key"

////
//static SSL_CTX * g_ssl_ctx = nullptr;
//static const SSL_METHOD * g_ssl_meth = nullptr;
//static int an_ssl_init(){
//	int rc = 0;
//
//	rc = SSL_library_init();
//	SSL_CHK_RV(rc, "SSL_library_init ");
//
//	SSL_load_error_strings();
//	OpenSSL_add_all_algorithms();
//
//	g_ssl_meth = SSLv23_server_method();
//	g_ssl_ctx = SSL_CTX_new(g_ssl_meth);
//	SSL_CHK_NULL(g_ssl_ctx, "SSL_CTX_new ");
//
//	// 是否要求校验对方证书 此处不验证客户端身份所以为： SSL_VERIFY_NONE
//	SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, nullptr);
//
//	// 加载CA的证书  
//	if (!SSL_CTX_load_verify_locations(g_ssl_ctx, AN_CERTCA, nullptr))
//	{
//		std::cout << "SSL_CTX_load_verify_locations ca cert error!" << std::endl;
//		ERR_print_errors_fp(stderr);
//		return -1;
//	}
//
//	// 加载自己的证书  
//	if (SSL_CTX_use_certificate_file(g_ssl_ctx, AN_CERTSERVER, SSL_FILETYPE_PEM) <= 0)
//	{
//		std::cout << "SSL_CTX_use_certificate_file server cert error!" << std::endl;
//		ERR_print_errors_fp(stderr);
//		return -1;
//	}
//
//	// 加载自己的私钥  私钥的作用是，ssl握手过程中，对客户端发送过来的随机
//	//消息进行加密，然后客户端再使用服务器的公钥进行解密，若解密后的原始消息跟
//	//客户端发送的消息一直，则认为此服务器是客户端想要链接的服务器
//	if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, AN_KEYSERVER, SSL_FILETYPE_PEM) <= 0)
//	{
//		std::cout << "SSL_CTX_use_PrivateKey_file server key error!" << std::endl;
//		ERR_print_errors_fp(stderr);
//		return -1;
//	}
//
//	// 判定私钥是否正确  
//	if (!SSL_CTX_check_private_key(g_ssl_ctx))
//	{
//		std::cout << "SSL_CTX_check_private_key error!" << std::endl;
//		ERR_print_errors_fp(stderr);
//		return -1;
//	}
//
//	return rc;
//}

//memory leak test
void EnableMemLeakCheck()
{
	int tmpFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	tmpFlag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag(tmpFlag);
}


void on_write(uv_write_t *req, int status)
{
	std::string log = fmt::format("=====on_write(req={:#08x}, status={})", (intptr_t)req, status);

	if (!status && req) {

		if (req->data) {
			free(req->data);
			req->data = nullptr;
		}
		free(req);
		req = nullptr;
	}

	anlog::getlogger()->info(log);
}

void on_close(uv_tls_t* sclient)
{
	std::string log = fmt::format("=====on_close(sclient={:#08x})", (intptr_t)sclient);

	//on_connect_cb 中的 uv_tls_t *sclient = (uv_tls_t*)malloc(sizeof(*sclient));
	free(sclient);
	sclient = nullptr;

	anlog::getlogger()->info(log);
}

/*
static const char * g_resp = R"(HTTP/1.1 200 OK
Server: anTSL1/1.0.0
Content-Type: text/html
Connection: keep-alive
Content-Length: 10

anTSL1
)";
*/

static const char * g_http_resp = "HTTP/1.1 200 OK\r\n"
"Server: anTSL1/1.0.0\r\n"
"Content-Type: text/html\r\n"
"Connection: keep-alive\r\n"
"Content-Length: 10\r\n"
"\r\n"
"\r\n"
"anTSL1\r\n";


//Callback for testing
// ssl 解密后的数据 回调
void on_read(uv_tls_t* clnt, int nread, uv_buf_t* dcrypted)
{
	if (nread <= 0) {
		switch (nread) {
		case UV_ECONNRESET: //异常断开，如客户端断开
			uv_tls_close(clnt, on_close);
			break;
		case UV_EOF: //主动断开
			uv_tls_close(clnt, on_close);
			break;
		case 0:
			//uv_tls_close(clnt, on_close);
			break;
		default:
			break;
		}
		

		anlog::getlogger()->info(fmt::format("=====on_read(clnt={:#08x}, errorcode={}, dcrypted={:#08x})", (intptr_t)clnt, nread, (intptr_t)dcrypted));
		return;
	}

	std::string log = fmt::format("=====on_read(clnt={:#08x}, nread={}, dcrypted={})", (intptr_t)clnt, nread, std::string(dcrypted->base, nread));

	
	//echo client
	uv_write_t *req = (uv_write_t*)malloc(sizeof(*req));
	assert(req != 0);
	req->data = nullptr;

	//int rc = uv_tls_write(req, clnt, dcrypted, on_write);
	//log += fmt::format(", uv_tls_write(req={:#08x}, clnt={:#08x}, dcrypted={})", (intptr_t)req, (intptr_t)clnt, std::string(dcrypted->base, nread));

	//临时http respone
	uv_buf_t tmp = { 0x00 };
	tmp.base = (char *)g_http_resp;
	tmp.len = strlen(g_http_resp);
	int rc = uv_tls_write(req, clnt, &tmp, on_write);
	log += fmt::format(", uv_tls_write(req={:#08x}, clnt={:#08x}, dcrypted={})", (intptr_t)req, (intptr_t)clnt, std::string(tmp.base, tmp.len));
	
	anlog::getlogger()->info(log);

	free(dcrypted->base);
	dcrypted->base = nullptr;
}

void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
	std::string log = fmt::format("=====alloc_cb(handle={:#08x}, size={})", (intptr_t)handle, size);

	buf->base = (char*)malloc(size);
	assert(buf->base != NULL && "Memory allocation failed");

	//memset(buf->base, 0, size);
	buf->len = size;
	

	anlog::getlogger()->info(log);
}

//第一步，服务端 接收连接
void on_connect_cb(uv_stream_t *server, int status)
{
	std::string log = fmt::format("=====on_connect_cb(uv_server={:#08x}, status={})", (intptr_t)server, status);
	
	if (status) {
		anlog::getlogger()->info(log);
		return;
	}
	uv_tls_t *s_srvr = CONTAINER_OF(server, uv_tls_t, socket_);

	//memory being freed at on_close
	uv_tls_t *sclient = (uv_tls_t*)malloc(sizeof(*sclient));
	int rc = uv_tls_init(server->loop, sclient);

	log += fmt::format(", uv_tls_init(loop={:#08x}, sclient={:#08x})={}", (intptr_t)server->loop, (intptr_t)sclient, rc);
	if (rc < 0) {
		anlog::getlogger()->error("uv_tls_init TLS setup error.");
		return;
	}

	rc = uv_tls_accept(s_srvr, sclient);

	log += fmt::format(", uv_tls_accept(s_tls={:#08x}, sclient={:#08x})={}", (intptr_t)s_srvr, (intptr_t)sclient, rc);

	if (!rc) {
		rc = uv_tls_read(sclient, alloc_cb, on_read);

		log += fmt::format(", uv_tls_read(sclient={:#08x})={}", (intptr_t)sclient, rc);
	}

	anlog::getlogger()->info(log);
}

uv_signal_t g_sig = { 0x00 };
static void signal_handler(uv_signal_t* req, int signum) {
	anlog::getlogger()->info(fmt::format("signal_handler received {} signal!", signum));

	uv_stop(g_loop);
}

uv_timer_t g_timerout = { 0x00 };
static void on_timer(uv_timer_t* req) {
	anlog::getlogger()->info(fmt::format("on_timer timeout!"));

	//uv_stop(g_loop);
}

//test
struct an_tls_session_s : public uv_tls_t {
	int sc_status_;
};

int main(int argc, char *argv[])
{
#ifdef _DEBUG
	EnableMemLeakCheck();

	//_CrtSetBreakAlloc(7997);
	//_CrtSetBreakAlloc(337);
	//_CrtSetBreakAlloc(336);
	//_CrtSetBreakAlloc(202);
	//_CrtSetBreakAlloc(201);
#endif
	//anlog::getlogger()->set_pattern("[%^%l%$] %v");
	anlog::getlogger()->set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%^%l%$] %v");

	/*int test = 285663375;
	bool b = test & 2;
	assert(!b);*/

	anlog::getlogger()->info("anTSL_server1 starting...");
    //std::cout << "Hello anTSL_server1..." << std::endl;
	int rc = 0;

	//init uv
	g_loop = uv_default_loop();
	if (nullptr == g_loop) {
		anlog::getlogger()->error("init uv loop faild.");
		//std::cout << "init uv loop faild." << std::endl;
		return -1;
	}

	//
	uv_signal_init(g_loop, &g_sig);
	uv_signal_start(&g_sig, signal_handler, SIGINT);

	////
	//uv_timer_init(g_loop, &g_timerout);
	//uv_timer_start(&g_timerout, on_timer, 5000, 1);

	//init ssl
	/*rc = an_ssl_init();
	if (-1 == rc) return rc;
	*/
	rc = tls_engine_inhale(AN_CERTCA, AN_CERTSERVER, AN_KEYSERVER, 0);
	if (ERR_TLS_OK != rc) {
		anlog::getlogger()->error(fmt::format("tls_engine_inhale faild,rc={}", rc));
		//std::cout << "tls_engine_inhale faild,rc=" << rc << std::endl;
		return rc;
	}

	/*
	an_tls_session_s * test = (an_tls_session_s*)malloc(sizeof *test);
	uv_tls_init(g_loop, test);

	uv_tcp_t * tcp = &test->socket_;
	an_tls_session_s * test2 = CONTAINER_OF(tcp, an_tls_session_s, socket_);
	*/

	//init tcp
	//rc = an_tcp_server_start();
	uv_tls_t *server = (uv_tls_t*)malloc(sizeof *server);
	if (uv_tls_init(g_loop, server) < 0) {
		free(server);
		server = nullptr;
		anlog::getlogger()->error("TLS setup error.");
		return  -1;
	}

	const int port = 9555;
	//struct sockaddr_in bind_addr = { 0x00 };
	struct sockaddr_storage bind_addr = { 0x00 };
	rc = uv_ip4_addr("0.0.0.0", port, (sockaddr_in*)&bind_addr);
	//rc = uv_ip6_addr("::", port, (sockaddr_in6*)&bind_addr);
	assert(!rc);
	rc = uv_tcp_bind(&(server->socket_), (struct sockaddr*)&bind_addr, 0);
	if (rc) {
		anlog::getlogger()->error(fmt::format("uv_tcp_bind,rc={},error={}", rc, uv_strerror(rc)));
		return -1;
	}

	rc = uv_tls_listen(server, 128, on_connect_cb);
	if (rc) {
		anlog::getlogger()->error(fmt::format("uv_tls_listen, rc={}, error={}", rc, uv_strerror(rc)));
		return -1;
	}
	anlog::getlogger()->info(fmt::format("Listening on {} ...", port));

	//
	rc = uv_run(g_loop, UV_RUN_DEFAULT);

	uv_signal_stop(&g_sig);
	uv_timer_stop(&g_timerout);

	uv_loop_close(g_loop);
	tls_engine_stop();

	free(server);
	server = nullptr;
	//SSL_CTX_free(g_ssl_ctx);

	anlog::getlogger()->info("anTSL_server1 exit!");
	anlog::getlogger()->flush();

	spdlog::shutdown();

#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif

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
