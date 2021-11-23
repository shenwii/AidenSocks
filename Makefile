include Makefile.inc

ifeq ($(OS),Windows_NT)
	UNAME_S := Windows_NT
else
	UNAME_S := $(shell uname -s)
endif

all:
	@gmake -f Makefile_asdns.mk
	@gmake -f Makefile_asgenkey.mk
ifeq ($(UNAME_S),Linux)
	@gmake -f Makefile_asred.mk
endif
	@gmake -f Makefile_assocks5.mk
	@gmake -f Makefile_asserver.mk

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
ifeq ($(UNAME_S),Linux)
	cp -fp $(ASDNS_BIN) $(ASGENKEN_BIN) $(ASRED_BIN) $(ASSOCKS5_BIN) $(ASSERVER_BIN) $(PREFIX_BIN)
else
	cp -fp $(ASDNS_BIN) $(ASGENKEN_BIN) $(ASSOCKS5_BIN) $(ASSERVER_BIN) $(PREFIX_BIN)
endif

uninstall:
ifeq ($(UNAME_S),Linux)
	rm -rf $(PREFIX)/$(ASDNS_BIN) $(PREFIX)/$(ASGENKEN_BIN) $(PREFIX)/$(ASRED_BIN) $(PREFIX)/$(ASSOCKS5_BIN) $(PREFIX)/$(ASSERVER_BIN)
else
	rm -rf $(PREFIX)/$(ASDNS_BIN) $(PREFIX)/$(ASGENKEN_BIN) $(PREFIX)/$(ASSOCKS5_BIN) $(PREFIX)/$(ASSERVER_BIN)
endif

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

.PHONY: all clean install uninstall
