#include "tlshelper.hh"

#include <argp.h>

#include <cstdio>
#include <stdexcept>

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
	printf("OpenSSL initialized\n");

	auto ctx = tls_make_client_context();
	if (args.caFile.size())
	{
		tls_load_ca_file(ctx, args.caFile);
	}
	tls_set_verify_peer_mode(ctx, 5);

	BIO_Ptr bio(BIO_new_ssl_connect(ctx.get()));
	if (!bio) {
		tls_fatal("BIO_new_ssl_connect");
	}
	tls_set_auto_retry(bio);

	BIO_set_conn_hostname(bio.get(), args.address.data());
	if (BIO_do_connect(bio.get()) <= 0) {
		tls_fatal("BIO_do_connect");
	}
	if (BIO_do_handshake(bio.get()) <= 0) {
		tls_fatal("BIO_do_handshake");
	}

	BIO_puts(bio.get(), "ping");
}
catch (std::exception &ex)
{
	printf("Exception: %s\n", ex.what());
}
