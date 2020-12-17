include Makefile.inc

ASGENKEN_SRCS = asgenkey.c base64.c
ASGENKEN_OBJS = $(patsubst %.c,$(OBJDIR)/%.o,$(ASGENKEN_SRCS))

all: $(ASGENKEN_BIN)

$(ASGENKEN_BIN): $(OBJDIR) $(BINDIR) $(ASGENKEN_OBJS)
	$(CC) -o $@ $(ASGENKEN_OBJS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: all
