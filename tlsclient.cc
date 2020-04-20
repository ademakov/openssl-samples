
#include <argp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstdio>
#include <stdexcept>
#include <memory>
#include <string>

//////////////////////////////////////////////////////////////////////////////
// TLS utils

struct SSL_CTX_Deleter
{
	void operator()(SSL_CTX *ctx) const noexcept
	{
		SSL_CTX_free(ctx);
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
using BIO_Ptr = std::unique_ptr<BIO, BIO_Deleter>;
using BIO_METHOD_Ptr = std::unique_ptr<BIO_METHOD, BIO_METHOD_Deleter>;

[[noreturn]] void
tls_fatal(const std::string& message)
{
	fprintf(stderr, "OpenSSL error: %s:\n", message.data());
	ERR_print_errors_fp(stderr);
	throw std::runtime_error(message);
}

void
tls_module_setup()
{
	int rc = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
				  | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
				  | OPENSSL_INIT_ADD_ALL_CIPHERS
				  | OPENSSL_INIT_ADD_ALL_DIGESTS
				  | OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
	if (!rc)
		tls_fatal("Failed to initialize");

	printf("OpenSSL initialized\n");
}

void
tls_module_cleanup() noexcept
{
        // Typically this is called automatically on thread exit. Have it here
	// for special cases.
	OPENSSL_cleanup();
}

void
tls_thread_cleanup() noexcept
{
        // Typically this is called automatically on thread exit. Have it here
	// for special cases.
	OPENSSL_thread_stop();
}

namespace {

SSL_CTX_Ptr
tls_make_context_helper(const SSL_METHOD *method)
{
	if (method == nullptr)
		tls_fatal("Failed to get SSL method");

	auto ctx = SSL_CTX_new(method);
	if (ctx == nullptr)
		tls_fatal("Failed to create SSL context");

	return SSL_CTX_Ptr(ctx);
}

} // namespace

SSL_CTX_Ptr
tls_make_client_context()
{
	return tls_make_context_helper(TLS_client_method());
}

SSL_CTX_Ptr
tls_make_server_context()
{
	return tls_make_context_helper(TLS_server_method());
}

void
tls_init_client_context(SSL_CTX_Ptr& ctx, const std::string& caFile)
{
	if (!SSL_CTX_load_verify_locations(ctx.get(), caFile.data(), nullptr)) {
		tls_fatal("Failed to load a CAfile");
	}
}

//////////////////////////////////////////////////////////////////////////////
// main

struct arguments
{
	std::string address = "localhost:4433";
	std::string caFile;
};

error_t
arg_parser(int key, char *arg, struct argp_state *state)
{
	auto args = static_cast<struct arguments *>(state->input);
	switch (key)
	{
	case ARGP_KEY_ARG:
		switch (state->arg_num)
		{
		default:
			argp_usage(state);
		case 0:
			args->address = arg;
			break;
		case 1:
			args->caFile = arg;
			break;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int
main(int ac, char *av[])
try
{
	arguments args;
	static argp argp = { 0, arg_parser, 0, "A basic TLS client" };
	argp_parse(&argp, ac, av, 0, 0, &args);

	tls_module_setup();

	auto ctx = tls_make_client_context();
	if (args.caFile.size())
	{
		tls_init_client_context(ctx, args.caFile);
	}

	BIO_Ptr bio(BIO_new_ssl_connect(ctx.get()));
	if (!bio) {
		tls_fatal("BIO_new_ssl_connect");
	}
	BIO_set_conn_hostname(bio.get(), args.address.data());
	if (BIO_do_connect(bio.get()) <= 0) {
		tls_fatal("BIO_do_connect");
	}

	//SSL ssl;
	//BIO_get_ssl(bio, &ssl);

}
catch (std::exception &ex)
{
	printf("Exception: %s\n", ex.what());
}
