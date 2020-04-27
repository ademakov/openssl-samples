#include "tlshelper.hh"

#include <argp.h>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>

class selfpipe
{
public:
	selfpipe()
	{
		if (pipe(fds) < 0) {
			throw std::runtime_error("pipe()");
		}
	}

	~selfpipe()
	{
		close(fds[0]);
		close(fds[1]);
	}

	int get_read_fd() const
	{
		return fds[0];
	}

	int get_write_fd() const
	{
		return fds[1];
	}

	void notify()
	{
		char data = 0;
		if (write(get_write_fd(), &data, sizeof(data)) != sizeof(data)) {
			throw std::runtime_error("pipe write()");
		}
	}

private:
	int fds[2];
};

struct arguments
{
	std::string address = "localhost:4433";
	std::string certificateFile;
	std::string privateKeyFile;
};

std::string g_storage;

error_t
arg_parser(int key, char *arg, struct argp_state *state)
{
	auto args = static_cast<struct arguments *>(state->input);
	switch (key) {
	case ARGP_KEY_ARG:
		switch (state->arg_num)	{
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
read_data(const BIO_Ptr& bio, char *data, int size, int min_bytes)
{
	int bytes = 0;
	while (size > 0) {
		int rc = BIO_read(bio.get(), data, size);
		if (rc <= 0) {
			break;
		}

		bytes += rc;
		if (bytes >= min_bytes) {
			break;
		}
		data += rc;
		size -= rc;
	}
	return bytes;
}

int
write_data(const BIO_Ptr& bio, char *data, int size)
{
	int bytes = 0;
	while (size > 0) {
		int rc = BIO_write(bio.get(), data, size);
		if (rc <= 0) {
			break;
		}

		bytes += rc;
		data += rc;
		size -= rc;
	}
	return bytes;
}

void
feed_thread(BIO_Ptr bio, std::string data)
{
	for (;;) {
		char buffer[1024];
		int rc = read_data(bio, buffer, sizeof buffer, 1);
		if (rc <= 0) {
			break;
		}
		data.append(buffer, rc);
	}

	BIO_ssl_shutdown(bio.get());
	printf("handled feed %zu\n", data.size());

	g_storage = std::move(data);
}

void
read_thread(BIO_Ptr bio)
{
	write_data(bio, g_storage.data(), g_storage.size());
	BIO_ssl_shutdown(bio.get());
	printf("handled read\n");
}

void
accept_client(const BIO_Ptr& acceptor)
{
	if (BIO_do_accept(acceptor.get()) <= 0) {
		tls_error("BIO_do_accept");
	}

	printf("accepted a client connection\n");

	BIO_Ptr client(BIO_pop(acceptor.get()));
	while (BIO_do_handshake(client.get()) <= 0) {
		if (!BIO_should_retry(client.get())) {
			tls_error("BIO_do_handshake");
		}
	}

	char buffer[1024];
	int rc = read_data(client, buffer, sizeof buffer, 4);
	if (rc == 4 && memcmp(buffer, "ping", 4) == 0) {
		BIO_puts(client.get(), "pong");
		BIO_ssl_shutdown(client.get());

		printf("handled ping\n");
	} else if (rc == 4 && memcmp(buffer, "read", 4) == 0) {
		std::thread(read_thread, std::move(client));
	} else if (rc >= 4 && memcmp(buffer, "feed", 4) == 0) {
		std::string data(buffer + 4, rc - 4);
		std::thread(feed_thread, std::move(client), std::move(data)).detach();
	} else {
		BIO_puts(client.get(), "error");
		BIO_ssl_shutdown(client.get());
	}
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
	if (args.certificateFile.size()) {
		tls_use_cert_and_key(ctx, args.certificateFile, args.privateKeyFile);
	}

	BIO_Ptr sbio(tls_make_server_BIO(ctx));
	tls_set_auto_retry(sbio);

	BIO_Ptr acceptor(BIO_new_accept(args.address.data()));
	if (!acceptor)
		tls_fatal("Failed to create acceptor");
	BIO_set_nbio(acceptor.get(), 1);
	BIO_set_nbio_accept(acceptor.get(), 1);
	BIO_set_accept_bios(acceptor.get(), sbio.release());
	if (BIO_do_accept(acceptor.get()) <= 0)
		tls_fatal("BIO_new_accept()");

	static selfpipe selfpipe;
	signal(SIGINT, [](int) { selfpipe.notify(); });
	signal(SIGPIPE, SIG_IGN);

	const int acceptor_fd = BIO_get_fd(acceptor.get(), nullptr);
	const int selfpipe_fd = selfpipe.get_read_fd();
	const int nfds = std::max(acceptor_fd, selfpipe_fd) + 1;
	for (;;) {
		printf("listenning...\n");

		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(acceptor_fd, &rfds);
		FD_SET(selfpipe_fd, &rfds);

		int rc = select(nfds, &rfds, nullptr, nullptr, nullptr);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			throw std::runtime_error("select()");
		}

		if (FD_ISSET(selfpipe_fd, &rfds))
			break;
		if (FD_ISSET(acceptor_fd, &rfds))
			accept_client(acceptor);
	}

	printf("quit\n");
	return 0;
}
catch (std::exception &ex)
{
	printf("Exception: %s\n", ex.what());
}
