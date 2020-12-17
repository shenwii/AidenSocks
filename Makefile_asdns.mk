include Makefile.inc

ASDNS_SRCS = asdns.c iconf.c common.c ascore.c base64.c aes.c thrdpool.c crc32.c asprot.c
ASDNS_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(ASDNS_SRCS))

all: $(ASDNS_BIN)

$(ASDNS_BIN): $(OBJDIR) $(BINDIR) $(ASDNS_OBJS)
	$(CC) -o $@ $(ASDNS_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
