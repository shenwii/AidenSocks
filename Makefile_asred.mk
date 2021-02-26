include Makefile.inc

ASRED_SRCS = asred.c iconf.c common.c ascore.c base64.c aes.c crc32.c asprot.c dnsprot.c
ASRED_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(ASRED_SRCS))

all: $(ASRED_BIN)

$(ASRED_BIN): $(OBJDIR) $(BINDIR) $(ASRED_OBJS)
	$(CC) -o $@ $(ASRED_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
