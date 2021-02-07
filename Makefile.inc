CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)

ASDNS_BIN = $(BINDIR)/as-dns
ASGENKEN_BIN = $(BINDIR)/as-genkey
ASRED_BIN = $(BINDIR)/as-red
ASSOCKS5_BIN = $(BINDIR)/as-socks5
ASSERVER_BIN = $(BINDIR)/as-server

CFLAGS += -Wall
LDFLAGS += -lssl -lcrypto -liniparser -lpthread

ifdef DEBUG
CFLAGS += -DDEBUG -g -O0
else
LDFLAGS += -s -Os
endif
