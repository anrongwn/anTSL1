
/*//////////////////////////////////////////////////////////////////////////////

 * Copyright (c) 2015 libuv-tls contributors

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
**////////////////////////////////////////////////////////////////////////////*/
#include "pch.h"
#include "uv_tls.h"


//wheel bio  write
static inline int wheel_bio_write(BIO *bio, const char * data, int len) {
	int rv = 0, npos = 0;;
	for (; npos < len; npos += rv) {
		rv = BIO_write(bio, (data + npos), (len - npos));
		if (rv <= 0) {
			if (BIO_should_retry(bio)) {
				rv = 0;
				continue;
			}
			else
			{
				return rv;
			}
		}
	}

	return npos;
}

//wheel bio read
static inline int wheel_bio_read(BIO *bio, char * data, int len) {
	int rv = 0, npos=0;
	for (; npos < len; npos += rv) {
		rv = BIO_read(bio, (data + npos), (len - npos));
		if (rv <= 0) {
			if (BIO_should_retry(bio)) {
				rv = 0;
				continue;
			}
			else {
				return rv;
			}
		}
	}
	return npos;
}

//wheel ssl write
static inline int wheel_ssl_write(SSL *ssl, char *buf, int len) {
	int rc = 0, npos = 0, ssl_ec = 0;

	while (npos<len) {
		rc = SSL_write(ssl, (void*)(buf + npos), len - npos);
		ssl_ec = SSL_get_error(ssl, rc);
		if (SSL_ERROR_NONE == ssl_ec) {
			if (rc > 0) {
				npos += rc;
			}
			else {
				rc = 0;
				ERR_print_errors_fp(stderr);
			}
		}
		else if (SSL_ERROR_WANT_READ == ssl_ec) {
			continue;
		}
		else if (SSL_ERROR_WANT_WRITE == ssl_ec) {
			continue;
		}
		else {
			ERR_print_errors_fp(stderr);
			npos = -1;
			break;
		}
	}

	return npos;
}

//wheel ssl read, node:no used.
static inline int wheel_ssl_read(SSL *ssl, char *buf, int len) {
	int rc = 0, npos = 0, ssl_ec = 0;

	while (npos < len) {
		rc = SSL_read(ssl, (void*)(buf + npos), len - npos);
		SSL_pending(ssl);

		ssl_ec = SSL_get_error(ssl, rc);
		if (SSL_ERROR_NONE == ssl_ec) {
			if (rc > 0) {
				npos += rc;
			}
			else {
				rc = 0;
				ERR_print_errors_fp(stderr);
			}
		}
		else if (SSL_ERROR_WANT_READ == ssl_ec) {
			continue;
		}
		else if (SSL_ERROR_WANT_WRITE == ssl_ec) {
			continue;
		}
		else {
			ERR_print_errors_fp(stderr);
			npos = -1;
			break;
		}
	}

	return npos;
}
//Auxilary
inline uv_stream_t* uv_tls_get_stream(uv_tls_t* tls)
{
    return  (uv_stream_t*) &tls->socket_;
}

int uv_tls_init(uv_loop_t *loop, uv_tls_t *tls)
{
	int rc = 0;
    rc = uv_tcp_init(loop, &tls->socket_);
	tls->socket_.data = tls;

    tls_engine *ng = &(tls->tls_eng);

    ng->ctx = get_tls_ctx();
    ng->ssl = nullptr;
    ng->ssl_bio_ = nullptr;
    ng->app_bio_ = nullptr;
	tls->oprn_state = STATE_INIT;
	tls->rd_cb = nullptr;
	tls->close_cb = nullptr;
	tls->on_tls_connect = nullptr;

	tls->data = nullptr;

    return rc;
}

//读 app_bio_，写 uv 
void stay_uptodate(uv_tls_t *tls, uv_alloc_cb uv__tls_alloc)
{
	std::string log = fmt::format("uv_tls::stay_uptodate(tls={:#08x})", (intptr_t)tls);
    uv_stream_t * client = uv_tls_get_stream(tls);

    int pending = BIO_pending(tls->tls_eng.app_bio_);

	log += fmt::format(", BIO_pending(app_bio={:#08x})={}", (intptr_t)tls->tls_eng.app_bio_, pending);

    if( pending > 0) {

        //Need to free the memory
		uv_buf_t mybuf = { 0x00 };

        if(uv__tls_alloc) {
            uv__tls_alloc((uv_handle_t*)client, pending, &mybuf);
        }

		int rv = 0;
		rv = wheel_bio_read(tls->tls_eng.app_bio_, mybuf.base, pending);
		/*while (rv < pending){
			rv += BIO_read(tls->tls_eng.app_bio_, (mybuf.base+rv), (pending-rv));
		}*/
		//rv = BIO_read(tls->tls_eng.app_bio_, mybuf.base, pending);
        assert( rv == pending );

		log += fmt::format(", BIO_read(app_bio={:#08x})={}, mybuf.base={:#08x}[ciphertext]", (intptr_t)tls->tls_eng.app_bio_, rv, (intptr_t)mybuf.base);

		//注意：uv_try_write 可能报 -4077 或 -4083 错误，表示client 断开了
		rv = uv_try_write(client, &mybuf, 1);
		//assert(rv == pending);
		
		log += fmt::format(", uv_try_write(client={:#08x})={}", (intptr_t)client, rv);

        free(mybuf.base);
		mybuf.base = nullptr;
        mybuf.base = 0;
    }

	anlog::getlogger()->info(log);
}

static void uv__tls_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(size);
    assert(buf->base != NULL && "Memory allocation failed");
    
	buf->len = size;
}

//handle only non fatal error currently
int uv__tls_err_hdlr(uv_tls_t* tls, const int err_code)
{
	std::string log = fmt::format("uv_tls::uv__tls_err_hdlr(tls={:#08x}, err_code={})", (intptr_t)tls, err_code);

	//ssl_read有数据
    if(err_code > 0) {
		anlog::getlogger()->info(log);
        return err_code;
    }

	//错误处理
	int ssl_error = SSL_get_error(tls->tls_eng.ssl, err_code);

	log += fmt::format(", SSL_get_error(ssl={:#08x}, err_code={})={}", (intptr_t)tls->tls_eng.ssl, err_code, ssl_error);
	anlog::getlogger()->info(log);

    switch (ssl_error) {
        case SSL_ERROR_NONE: //0
        case SSL_ERROR_SSL:  // 1
            ERR_print_errors_fp(stderr);
            //don't break, flush data first

        case SSL_ERROR_WANT_READ: // 2
        case SSL_ERROR_WANT_WRITE: // 3
        case SSL_ERROR_WANT_X509_LOOKUP:  // 4
            stay_uptodate(tls, uv__tls_alloc);
            break;
        case SSL_ERROR_ZERO_RETURN: // 5
        case SSL_ERROR_SYSCALL: //6
        case SSL_ERROR_WANT_CONNECT: //7
        case SSL_ERROR_WANT_ACCEPT: //8
            //ERR_print_errors_fp(stderr);
        default:
            return err_code;
    }

	
    return err_code;
}

void after_close(uv_handle_t * hdl)
{
    uv_tls_t *tls = CONTAINER_OF((uv_tcp_t*)hdl, uv_tls_t, socket_);
    if(tls->close_cb) {
		tls->close_cb(tls);
    }
}

int uv__tls_close(uv_tls_t* sclient)
{
	std::string log = fmt::format("uv_tls::uv__tls_close(sclient={:#08x})", (intptr_t)sclient);

    tls_engine *ng = &(sclient->tls_eng);
    int rv = SSL_shutdown(ng->ssl);
    uv__tls_err_hdlr(sclient, rv);
	log += fmt::format(", SSL_shutdown 1 (ssl={:#08x})={}", (intptr_t)ng->ssl, rv);

    if( rv == 0) {
		sclient->oprn_state = STATE_CLOSING;
        rv = SSL_shutdown(ng->ssl);
        uv__tls_err_hdlr(sclient, rv);

		log += fmt::format(", SSL_shutdown 2 (ssl={:#08x})={}", (intptr_t)ng->ssl, rv);
    }

    if( rv == 1) {
		sclient->oprn_state = STATE_CLOSING;
    }

	//
    BIO_free(ng->app_bio_);
    ng->app_bio_ = nullptr;
	ng->ssl_bio_ = nullptr;
    SSL_free(ng->ssl);
    ng->ssl = nullptr;

	//关闭 uv_tcp_h client
    uv_close( (uv_handle_t*)uv_tls_get_stream(sclient), after_close);

	anlog::getlogger()->info(log);

    return rv;
}

//shutdown the ssl session then stream
int uv_tls_close(uv_tls_t* session, tls_close_cb cb)
{
    session->close_cb = cb;
    return  uv__tls_close(session);
}

int uv__tls_handshake(uv_tls_t* tls)
{
	anlog::getlogger()->info(fmt::format("uv_tls::uv__tls_handshake(tls={:#08x}), oprn_state={}", (intptr_t)tls, tls->oprn_state));

	//已经握手
    if( tls->oprn_state & STATE_IO) {
        return 1;
    }

	//发起握手
    int rv = 0;
    rv = SSL_do_handshake(tls->tls_eng.ssl);
	anlog::getlogger()->info(fmt::format("uv_tls::uv__tls_handshake(tls={:#08x}), oprn_state={}, SSL_do_handshake(ssl={:#08x})={}",\
		(intptr_t)tls, tls->oprn_state, (intptr_t)(intptr_t)tls->tls_eng.ssl, rv));

    uv__tls_err_hdlr(tls, rv);
    tls->oprn_state = STATE_HANDSHAKING;

    if(rv == 1) {
        tls->oprn_state = STATE_IO;

        if(tls->on_tls_connect) {
            assert(tls->con_req);
            tls->on_tls_connect(tls->con_req, 0);
        }
    }

    return rv;
}

int uv_tls_shutdown(uv_tls_t* session)
{
    assert( session != NULL && "Invalid session");

    SSL_CTX_free(session->tls_eng.ctx);
    session->tls_eng.ctx = NULL;

    return 0;
}


uv_buf_t encode_data(uv_tls_t* sessn, uv_buf_t *data2encode)
{
    ////加密 data2encode 数据，发给client
    //int rv = SSL_write(sessn->tls_eng.ssl, data2encode->base, data2encode->len); 
	/*int rv = 0;
	while (rv < (int)data2encode->len) {
		rv += SSL_write(sessn->tls_eng.ssl, (data2encode->base+rv), (data2encode->len-rv));
	}*/
	int rv = wheel_ssl_write(sessn->tls_eng.ssl, data2encode->base, data2encode->len);
	assert(rv == data2encode->len);

	anlog::getlogger()->info(fmt::format("uv_tls::encode_data(sessn={:#08x}, data2encode->base={}, data2encode->len={}), SSL_write={}", (intptr_t)sessn, \
		std::string(data2encode->base, data2encode->len), data2encode->len, rv));

    int pending = 0;
	uv_buf_t encoded_data = { 0x00 };
    if( (pending = BIO_pending(sessn->tls_eng.app_bio_) ) > 0 ) {

        encoded_data.base = (char*)malloc(pending);
        encoded_data.len = pending;

		rv = 0;
		rv = wheel_bio_read(sessn->tls_eng.app_bio_, encoded_data.base, pending);
		/*while (rv < pending) {
			rv += BIO_read(sessn->tls_eng.app_bio_, (encoded_data.base + rv), (pending - rv));
		}*/
        //rv = BIO_read(sessn->tls_eng.app_bio_, encoded_data.base, pending); //经ssl 加密 data2encode 数据
		assert(rv == pending);
		encoded_data.len = rv;

		anlog::getlogger()->info(fmt::format("uv_tls::encode_data(), BIO_read(app_bio_={:#08x})={}, encoded_data.base={:#08x}[ciphertext], encoded_data.len={}", (intptr_t)sessn->tls_eng.app_bio_, \
			rv, (intptr_t)encoded_data.base, encoded_data.len));
    }

    return encoded_data;
}

int uv_tls_write(uv_write_t* req, uv_tls_t *client, uv_buf_t *buf, uv_write_cb on_tls_write)
{
	std::string log = fmt::format("uv_tls::uv_tls_write(req={:#08x}, client={:#08x}, buf={:#08x})", (intptr_t)req, (intptr_t)client, (intptr_t)buf);
	
    const uv_buf_t data = encode_data(client, buf);

	log += fmt::format(", encode_data=data.base={:#08x}[ciphertext],data.len={}", (intptr_t)data.base, data.len);

	req->data = data.base;

    int rv = uv_write(req, uv_tls_get_stream(client), &data, 1, on_tls_write);
    //free(data.base);---
	
	log += fmt::format(",uv_write(req={:#08x}, client={:#08x})={}", (intptr_t)req, (intptr_t)client, rv);

	anlog::getlogger()->info(log);

    return rv;
}

//所有 ssl 读流程操作，如完成握手
int uv__tls_read(uv_tls_t* tls, uv_buf_t* dcrypted, int sz)
{
	std::string log = fmt::format("uv_tls::uv__tls_read(tls={:#08x}, dcrypted={:#08x}, sz={})", (intptr_t)tls, (intptr_t)dcrypted, sz);
	
	//判断是否握手
	int ssl_is_init = SSL_is_init_finished(tls->tls_eng.ssl);
	log += fmt::format(", SSL_is_init_finished={}", ssl_is_init);
    if( !ssl_is_init ) {
        if( 1 != uv__tls_handshake(tls)) {
            //recheck if handshake is complete now

			log += ",uv__tls_handshake!=1.";
			anlog::getlogger()->info(log);
            return STATE_HANDSHAKING;
        }
    }

    //clean the slate
    memset(dcrypted->base, 0x00, sz);

	//从ssl 解密数据；注意：SSL_read 确保每次读取一条完整记录或失败
    int rv = SSL_read(tls->tls_eng.ssl, dcrypted->base, sz);
    uv__tls_err_hdlr(tls, rv); //SSL_read 无数据时的，错误处理;rv>=0，无须处理

	dcrypted->len = rv;
	log += fmt::format(",SSL_read(ssl={:#08x})={}", (intptr_t)tls, rv);

	//回调通知 实际的解密数据 处理
    if( tls->rd_cb) {
		log += fmt::format(", tls->rd_cb={:#08x}", (intptr_t)tls->rd_cb);
        tls->rd_cb(tls, rv, dcrypted);
    }

	anlog::getlogger()->info(log);
    return rv;
}

//实际 uv read 入口，所有buf 密文
void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
	std::string log = fmt::format("uv_tls::on_tcp_read(client={:#08x}, nread={}, buf={:#08x}[ciphertext])", (intptr_t)client, nread, (intptr_t)buf);
	
    uv_tls_t *tls = CONTAINER_OF(client, uv_tls_t, socket_);
    assert(tls != NULL);

    if( nread <= 0 && (tls->oprn_state & STATE_IO)) //client 异常断开
	{
		log += fmt::format(", uv errorcode={} <= 0 && ( tls->oprn_state={} & STATE_IO)", nread, tls->oprn_state);
		tls->rd_cb(tls, nread, (uv_buf_t*)buf);
	}
	else if (nread <= 0) //uv_eof -4095可能握手不成功，client主动断开
	{
		log += fmt::format(", uv errorcode={}, tls->oprn_state={}", nread, tls->oprn_state);
		tls->rd_cb(tls, nread, (uv_buf_t*)buf);
	}
    else //正常数据
	{
		int rv = 0;
		rv = wheel_bio_write(tls->tls_eng.app_bio_, buf->base, nread);
		assert(rv == nread);
		
        //int rv = BIO_write(tls->tls_eng.app_bio_, buf->base, nread);
		log += fmt::format(", BIO_write(app_bio_={:#08x}, buf->base={}[ciphertext], nread={})={}", (intptr_t)tls->tls_eng.app_bio_, std::string(buf->base, nread), nread, rv);
		//BIO_flush(tls->tls_eng.app_bio_);

		//从ssl 中解密或完成握手
		rv = uv__tls_read(tls, (uv_buf_t*)buf, nread);
		log += fmt::format(", uv__tls_read(tls={:#08x})={}", (intptr_t)tls, rv);
    }
    free(buf->base);

	anlog::getlogger()->info(log);
}

//uv_alloc_cb is unused, but here for cosmetic reasons
//Need improvement ,
int uv_tls_read(uv_tls_t* client, uv_alloc_cb uv__tls_alloc, tls_rd_cb on_read)
{
	anlog::getlogger()->info(fmt::format("uv_tls::uv_tls_read(client={:#08x}, uv_alloc_cb={:#08x}, tls_rd_cb={:#08x})", (intptr_t)client, (intptr_t)uv__tls_alloc, (intptr_t)on_read));

    client->rd_cb = on_read;
    return 0;
}

void on_tcp_conn(uv_connect_t* c, int status)
{
    uv_tls_t *sclnt = (uv_tls_t *)c->handle->data;
    assert( sclnt != 0);

    if(status < 0) {
        sclnt->on_tls_connect(c, status);
    }
    else { //tcp connection established
        uv__tls_handshake(sclnt);
        uv_read_start((uv_stream_t*)&sclnt->socket_, uv__tls_alloc, on_tcp_read);
    }
}

static int allocate_ssl(tls_engine *tls_ngin, int endpt_role)
{
	std::string log = fmt::format("uv_tls::allocate_ssl(tls_engine={:#08x},endpt_role={})", (intptr_t)tls_ngin, endpt_role);
	
    tls_ngin->ssl = SSL_new(tls_ngin->ctx);

	log += fmt::format(", tls_ngin->ssl=SSL_new(ctx={:#08x})={:#08x}", (intptr_t)tls_ngin->ctx, (intptr_t)tls_ngin->ssl);
    if(!tls_ngin->ssl) {
		anlog::getlogger()->info(log);
        return ERR_TLS_ERROR;
    }
    
    if( endpt_role == 1) {
        SSL_set_accept_state(tls_ngin->ssl);
    }
    else {
        //set in client mode
        SSL_set_connect_state(tls_ngin->ssl);
    }

    //use default buf size for now.
	int rc = BIO_new_bio_pair(&(tls_ngin->ssl_bio_), 0, &(tls_ngin->app_bio_), 0);
	log += fmt::format(", BIO_new_bio_pair(ssl_bio_={:#08x}, app_bio_={:#08x})={}", (intptr_t)tls_ngin->ssl_bio_, (intptr_t)tls_ngin->app_bio_, rc);
    if( !rc ) {
		anlog::getlogger()->info(log);
        return ERR_TLS_ERROR;
    }

	//关联 ssl 操作的bio, 所有ssl_write、ssl_read 都是通过此bio操作，用户进程不直接操作。
    SSL_set_bio(tls_ngin->ssl, tls_ngin->ssl_bio_, tls_ngin->ssl_bio_);

	anlog::getlogger()->info(log);

    return  ERR_TLS_OK;
}


int uv_tls_connect(uv_connect_t *req, uv_tls_t* tls, const struct sockaddr* addr, uv_connect_cb cb)
{
	std::string log = fmt::format("uv_tls::uv_tls_connect(req={:#08x},tls={:#08x})", (intptr_t)req, (intptr_t)tls);

    tls_engine *tls_ngin = &(tls->tls_eng);
    
	int rv = allocate_ssl(tls_ngin, 0);
    if(rv != ERR_TLS_OK) {
		log += ", allocate_ssl!=ERR_TLS_OK";
		anlog::getlogger()->info(log);
        return  rv;
    }

    tls->on_tls_connect = cb;
    tls->con_req = req;

	rv = uv_tcp_connect(req, &(tls->socket_), addr, on_tcp_conn);

	log += fmt::format(",tls->on_tls_connect={:#08x}, tls->con_req={:#08x}, uv_tcp_connect={}", (intptr_t)cb, (intptr_t)req, rv);
	anlog::getlogger()->info(log);

	return rv;
}

int uv_tls_accept(uv_tls_t* server, uv_tls_t* client)
{
	//anlog::getlogger()->info(fmt::format("uv_tls::uv_tls_accept(server={:#08x}, client={:#08x})", (intptr_t)server, (intptr_t)client));

    uv_stream_t* clnt = uv_tls_get_stream(client);
    assert(clnt != 0);
    
    uv_stream_t* srvr = uv_tls_get_stream(server);
    assert(srvr != 0);

    int rv = uv_accept( srvr, clnt);

	std::string log = fmt::format("uv_tls::uv_tls_accept(tls_server={:#08x}, tls_client={:#08x}), uv_accept(uv_srvr={:#08x}, uv_clnt={:#08x})={}", \
		(intptr_t)server, (intptr_t)client, (intptr_t)srvr, (intptr_t)clnt, rv);

    if (rv < 0) {
		anlog::getlogger()->info(log);
        return rv;
    }

    srvr->data = client;
    clnt->data = server;

    tls_engine *tls_ngin = &(client->tls_eng);

    //server role
    rv = allocate_ssl( tls_ngin, 1);
    if(rv != ERR_TLS_OK) {
		log += ", allocate_ssl!=ERR_TLS_OK";
		anlog::getlogger()->info(log);
        return  rv;
    }

	rv = uv_read_start(clnt, uv__tls_alloc, on_tcp_read);

	log += fmt::format(", uv_read_start(clnt={:#08x}, on_tcp_read)={}", (intptr_t)clnt, rv);
	anlog::getlogger()->info(log);

	return rv;
}

int uv_tls_listen(uv_tls_t *server, const int backlog, uv_connection_cb on_new_connect )
{
    uv_stream_t *strm = uv_tls_get_stream(server);
    assert(strm != NULL);

	int rc = 0;
	rc = uv_listen(strm, backlog, on_new_connect);

	anlog::getlogger()->info(fmt::format("uv_tls::uv_tls_listen(tls_server={:#08x}, backlog={}), uv_listen(strm={:#08x})={}", (intptr_t)server, backlog, (intptr_t)strm, rc));
	return rc;
}
