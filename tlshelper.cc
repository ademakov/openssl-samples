#include "tlshelper.hh"

#include <cstdio>
#include <stdexcept>

[[noreturn]] void
tls_fatal(const std::string& message)
{
	fprintf(stderr, "OpenSSL error: %s:\n", message.data());
	ERR_print_errors_fp(stderr);
	throw std::runtime_error(message);
}

