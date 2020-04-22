
CXXFLAGS=-std=c++17 -Wall -O1 -pthread
LDLIBS=-lssl -lcrypto

LINK.o=$(LINK.cc)

.PHONY: all
all: tlsclient tlsserver

tlsclient: tlsclient.o tlshelper.o
tlsserver: tlsserver.o tlshelper.o

tlshelper.o: tlshelper.cc tlshelper.hh
tlsclient.o: tlsclient.cc tlshelper.hh
tlsclient.o: tlsserver.cc tlshelper.hh

.PHONY: clean
clean:
	rm -fv *.o tlsclient tlsserver
