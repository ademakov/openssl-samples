#include "tlshelper.hh"

#include <argp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

enum opmode
{
	PING,
	FEED,
	READ,
};

struct arguments
{
	opmode mode = PING;
	std::string address = "localhost:4433";
	std::string caFile;
	std::string feedFile;
};

error_t
arg_parser(int key, char *arg, struct argp_state *state)
{
	auto args = static_cast<struct arguments *>(state->input);
	switch (key) {
	case 'f':
		args->mode = FEED;
		args->feedFile = arg;
		break;
	case 'r':
		args->mode = READ;
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
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
	static argp_option options[] = {
		{ "feed", 'f', "FILE", 0, "feed data to server" },
		{ "read", 'r', 0, 0, "read data from server" },
		{ 0 }
	};
	static argp argp = { options, arg_parser, 0, "A basic TLS client" };
	argp_parse(&argp, ac, av, 0, 0, &args);

	std::vector<char> feedData;
	if (args.mode == FEED) {
		int fd = open(args.feedFile.data(), O_RDONLY);
		if (fd < 0) {
			throw std::runtime_error("Failed to open the feed file");
		}

		struct stat st;
		if (fstat(fd, &st) < 0) {
			throw std::runtime_error("Failed to stat the feed file");
		}

		feedData.resize(st.st_size);
		if (read(fd, feedData.data(), st.st_size) != st.st_size) {
			throw std::runtime_error("Failed to read the feed file");
		}
	}

	tls_module_setup();
	printf("OpenSSL initialized\n");

	auto ctx = tls_make_client_context();
	if (args.caFile.size()) {
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

	switch (args.mode) {
	case PING:
		BIO_puts(bio.get(), "ping");
		break;
	case FEED:
		BIO_puts(bio.get(), "feed");
		BIO_write(bio.get(), feedData.data(), feedData.size());
		break;
	case READ:
		BIO_puts(bio.get(), "read");
		break;
	}

	for (;;) {
		char buffer[1024];
		int length = BIO_read(bio.get(), buffer, sizeof buffer - 1);
		if (length <= 0)
			break;

		buffer[length] = 0;
		printf("%s", buffer);
	}
	printf("\n");
}
catch (std::exception &ex)
{
	printf("Exception: %s\n", ex.what());
}
