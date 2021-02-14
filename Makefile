include Makefile.inc

all:
	@make -f Makefile_asdns.mk
	@make -f Makefile_asgenkey.mk
ifneq ($(OS),Windows_NT)
	@make -f Makefile_asred.mk
endif
	@make -f Makefile_assocks5.mk
	@make -f Makefile_asserver.mk

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(ASDNS_BIN) $(ASGENKEN_BIN) $(ASRED_BIN) $(ASSOCKS5_BIN) $(ASSERVER_BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(ASDNS_BIN) $(PREFIX)/$(ASGENKEN_BIN) $(PREFIX)/$(ASRED_BIN) $(PREFIX)/$(ASSOCKS5_BIN) $(PREFIX)/$(ASSERVER_BIN)

.PHONY: all clean install uninstall
