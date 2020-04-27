#include "tlshelper.hh"

#include <cstdio>
#include <stdexcept>

void
tls_error(const std::string& message)
{
	fprintf(stderr, "OpenSSL error: %s:\n", message.data());
	ERR_print_errors_fp(stderr);
}

[[noreturn]] void
tls_fatal(const std::string& message)
{
	tls_error(message);
	throw std::runtime_error(message);
}
