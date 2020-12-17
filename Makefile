include Makefile.inc

all:
	@make -f Makefile_asdns.mk
	@make -f Makefile_asgenkey.mk
	@make -f Makefile_asred.mk
	@make -f Makefile_assocks5.mk
	@make -f Makefile_asserver.mk

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(GSDNS_BIN) $(GSGENKEN_BIN) $(GSRED_BIN) $(GSSOCKS5_BIN) $(GSSERVER_BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(GSDNS_BIN) $(PREFIX)/$(GSGENKEN_BIN) $(PREFIX)/$(GSRED_BIN) $(PREFIX)/$(GSSOCKS5_BIN) $(PREFIX)/$(GSSERVER_BIN)

.PHONY: all clean install uninstall
