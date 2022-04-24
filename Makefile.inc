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
LDFLAGS += -lssl -lcrypto -liniparser

ifeq ($(OS),Windows_NT)
CFLAGS += -D_WIN32_WINNT=0x0600
LDFLAGS += -lws2_32 -liphlpapi
endif

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -g -O0
else
LDFLAGS += -s -Os
endif
