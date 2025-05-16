CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lgmp -lm

# Build directories
OBJDIR = dist/obj
BINDIR = dist/bin

# Source files
SRC_SYM = main_sym.c \
		src/symmetric/core/aes.c \
		src/symmetric/modes/gcm.c \
		src/symmetric/modes/common.c \
		src/symmetric/core/des.c \
		src/symmetric/modes/cfb.c \

SRC_ASYM = main_asym.c \
		src/asymmetric/rsa.c \



# Object files
OBJ_SYM = $(SRC_SYM:%.c=$(OBJDIR)/%.o)
OBJ_ASYM = $(SRC_ASYM:%.c=$(OBJDIR)/%.o)


# Main target - symmetric crypto tool
all: $(BINDIR)/crypto_sym $(BINDIR)/crypto_asym

$(BINDIR)/crypto_sym: $(OBJ_SYM)
	@echo "Linking $@..."
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJ_SYM)
	@echo "Build complete!"

$(BINDIR)/crypto_asym: $(OBJ_ASYM)
	@echo "Linking $@..."
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJ_ASYM) $(LDFLAGS)
	@echo "Build complete!"

# Generic compilation rule
$(OBJDIR)/%.o: %.c
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -rf dist
	@echo "Clean complete!"
.PHONY: all clean
debug:
	@echo "Symmetric source files:"
	@for file in $(SRC_SYM); do echo "  $$file"; done
	@echo "Asymmetric source files:"
	@for file in $(SRC_ASYM); do echo "  $$file"; done