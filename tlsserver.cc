#include "tlshelper.hh"

#include <argp.h>
#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <stdexcept>

struct arguments
{
	std::string address = "localhost:4433";
	std::string certificateFile;
	std::string privateKeyFile;
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
			args->certificateFile = arg;
			break;
		case 2:
			args->privateKeyFile = arg;
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
	static argp argp = { 0, arg_parser, 0, "A basic TLS server" };
	argp_parse(&argp, ac, av, 0, 0, &args);

	tls_module_setup();
	printf("OpenSSL initialized\n");

	auto ctx = tls_make_server_context();
	if (args.certificateFile.size())
	{
		tls_use_cert_and_key(ctx, args.certificateFile, args.privateKeyFile);
	}

	BIO_Ptr acceptor(BIO_new_accept(args.address.data()));
	if (!acceptor)
		tls_fatal("Failed to create acceptor");
	if (BIO_do_accept(acceptor.get()) <= 0)
		tls_fatal("BIO_new_accept");

	BIO_Ptr sbio(tls_make_server_BIO(ctx));
	tls_set_auto_retry(sbio);
	BIO_set_accept_bios(acceptor.get(), sbio.release());

	static int acceptor_fd = BIO_get_fd(acceptor.get(), nullptr);
	signal(SIGINT, [](int) { close(acceptor_fd); });
	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		if (BIO_do_accept(acceptor.get()) <= 0) {
			break;
		}

		printf("accepted a client connection\n");

		BIO_Ptr client(BIO_pop(acceptor.get()));
		if (BIO_do_handshake(client.get()) <= 0) {
			tls_fatal("BIO_do_handshake");
		}

		char buffer[200];
		while (BIO_read(client.get(), buffer, sizeof buffer) > 0) {
			printf("%s\n", buffer);
		}
	}

	printf("quit\n");
	return 0;
}
catch (std::exception &ex)
{
	printf("Exception: %s\n", ex.what());
}
