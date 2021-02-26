include Makefile.inc

ASSERVER_SRCS = asserver.c iconf.c common.c ascore.c base64.c aes.c crc32.c asprot.c dnsprot.c
ASSERVER_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(ASSERVER_SRCS))

all: $(ASSERVER_BIN)

$(ASSERVER_BIN): $(OBJDIR) $(BINDIR) $(ASSERVER_OBJS)
	$(CC) -o $@ $(ASSERVER_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
