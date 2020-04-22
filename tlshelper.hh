#pragma once

#include <memory>
#include <thread>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

struct SSL_CTX_Deleter
{
	void operator()(SSL_CTX *ctx) const noexcept
	{
		SSL_CTX_free(ctx);
	}
};

struct SSL_Deleter
{
	void operator()(SSL *ctx) const noexcept
	{
		SSL_free(ctx);
	}
};

struct BIO_Deleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free_all(bio);
	}
};

struct BIO_METHOD_Deleter
{
	void operator()(BIO_METHOD *method) const noexcept
	{
		BIO_meth_free(method);
	}
};

using SSL_CTX_Ptr = std::unique_ptr<SSL_CTX, SSL_CTX_Deleter>;
using SSL_Ptr = std::unique_ptr<SSL, SSL_Deleter>;
using BIO_Ptr = std::unique_ptr<BIO, BIO_Deleter>;
using BIO_METHOD_Ptr = std::unique_ptr<BIO_METHOD, BIO_METHOD_Deleter>;

[[noreturn]] void
tls_fatal(const std::string& message);

inline void
tls_module_setup()
{
	int rc = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
				  | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
				  | OPENSSL_INIT_ADD_ALL_CIPHERS
				  | OPENSSL_INIT_ADD_ALL_DIGESTS
				  | OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
	if (!rc) {
		tls_fatal("Failed to initialize");
	}
}

inline void
tls_module_cleanup() noexcept
{
        // Typically this is called automatically on thread exit. Have it here
	// for special cases.
	OPENSSL_cleanup();
}

inline void
tls_thread_cleanup() noexcept
{
        // Typically this is called automatically on thread exit. Have it here
	// for special cases.
	OPENSSL_thread_stop();
}

namespace detail {

inline SSL_CTX_Ptr
tls_make_context_helper(const SSL_METHOD *method)
{
	if (method == nullptr)
		tls_fatal("Failed to get SSL method");

	auto ctx = SSL_CTX_new(method);
	if (!ctx) {
		tls_fatal("Failed to create SSL context");
	}
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		tls_fatal("SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)");
	}

	return SSL_CTX_Ptr(ctx);
}

inline SSL_Ptr
tls_make_socket_helper(const SSL_CTX_Ptr& ctx, int fd, bool auto_close)
{
	BIO_Ptr bio(BIO_new_socket(fd, auto_close ? BIO_CLOSE : BIO_NOCLOSE));
	if (!bio) {
		tls_fatal("Failed to create BIO structure");
	}

	auto ssl = SSL_new(ctx.get());
	if (!ssl) {
		tls_fatal("Failed to create SSL structure");
	}

	SSL_set_bio(ssl, bio.get(), bio.get());
	bio.release();

	return SSL_Ptr(ssl);
}

inline SSL*
tls_get_ssl(const BIO_Ptr& bio)
{
	SSL* ssl = nullptr;
	BIO_get_ssl(bio.get(), &ssl);
	if (!ssl) {
		tls_fatal("BIO_get_ssl()");
	}
	return ssl;
}

} // namespace

inline SSL_CTX_Ptr
tls_make_client_context()
{
	return detail::tls_make_context_helper(TLS_client_method());
}

inline SSL_CTX_Ptr
tls_make_server_context()
{
	return detail::tls_make_context_helper(TLS_server_method());
}

inline void
tls_set_verify_peer_mode(const SSL_CTX_Ptr& ctx, int depth = 0)
{
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
	if (depth) {
		SSL_CTX_set_verify_depth(ctx.get(), depth);
	}
}

inline void
tls_load_ca_file(const SSL_CTX_Ptr& ctx, const std::string& file)
{
	if (!SSL_CTX_load_verify_locations(ctx.get(), file.data(), nullptr)) {
		tls_fatal("Failed to load a CAfile");
	}
}

inline void
tls_use_cert_and_key(const SSL_CTX_Ptr& ctx, const std::string& cert, const std::string& key)
{
	if (!SSL_CTX_use_certificate_chain_file(ctx.get(), cert.data())) {
		tls_fatal("SSL_CTX_use_certificate_chain_file");
	}
	if (!SSL_CTX_use_PrivateKey_file(ctx.get(), key.data(), SSL_FILETYPE_PEM)) {
		tls_fatal("SSL_CTX_use_PrivateKey_file");
	}
	if (!SSL_CTX_check_private_key(ctx.get())) {
		tls_fatal("SSL_CTX_check_private_key");
	}
}

inline SSL_Ptr
tls_make_client(const SSL_CTX_Ptr& ctx, int fd, bool auto_close)
{
	SSL_Ptr ssl = detail::tls_make_socket_helper(ctx, fd, auto_close);
	SSL_set_connect_state(ssl.get());
	return ssl;
}

inline SSL_Ptr
tls_make_server(const SSL_CTX_Ptr& ctx, int fd, bool auto_close)
{
	SSL_Ptr ssl = detail::tls_make_socket_helper(ctx, fd, auto_close);
	SSL_set_accept_state(ssl.get());
	return ssl;
}

inline BIO_Ptr
tls_make_client_BIO(const SSL_CTX_Ptr& ctx)
{
	auto bio = BIO_new_ssl(ctx.get(), 1);
	if (!bio) {
		tls_fatal("BIO_new_ssl");
	}
	return BIO_Ptr(bio);
}

inline BIO_Ptr
tls_make_server_BIO(const SSL_CTX_Ptr& ctx)
{
	auto bio = BIO_new_ssl(ctx.get(), 0);
	if (!bio) {
		tls_fatal("BIO_new_ssl");
	}
	return BIO_Ptr(bio);
}

inline void
tls_set_auto_retry(const SSL_Ptr& ssl)
{
	SSL_set_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
}

inline void
tls_clear_auto_retry(const SSL_Ptr& ssl)
{
	SSL_clear_mode(ssl.get(), SSL_MODE_AUTO_RETRY);
}

inline void
tls_set_auto_retry(const BIO_Ptr& bio)
{
	SSL_set_mode(detail::tls_get_ssl(bio), SSL_MODE_AUTO_RETRY);
}

inline void
tls_clear_auto_retry(const BIO_Ptr& bio)
{
	SSL_clear_mode(detail::tls_get_ssl(bio), SSL_MODE_AUTO_RETRY);
}
