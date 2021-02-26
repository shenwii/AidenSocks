include Makefile.inc

ASSOCKS5_SRCS = assocks5.c iconf.c common.c ascore.c base64.c aes.c crc32.c asprot.c dnsprot.c
ASSOCKS5_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(ASSOCKS5_SRCS))

all: $(ASSOCKS5_BIN)

$(ASSOCKS5_BIN): $(OBJDIR) $(BINDIR) $(ASSOCKS5_OBJS)
	$(CC) -o $@ $(ASSOCKS5_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
