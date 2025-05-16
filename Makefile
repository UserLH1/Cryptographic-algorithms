CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude

# Build directories
OBJDIR = dist/obj
BINDIR = dist/bin

# Source files
SRC = 	main_sym.c \
		src/symmetric/core/aes.c \
		src/symmetric/modes/gcm.c \
		src/symmetric/modes/common.c

# Object files
OBJ = $(SRC:%.c=$(OBJDIR)/%.o)

# Main target - symmetric crypto tool
all: $(BINDIR)/crypto_sym

$(BINDIR)/crypto_sym: $(OBJ)
	@echo "Linking $@..."
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJ)
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
	@echo "Source files:"
	@for file in $(SRC); do echo "  $$file"; done
	@echo "Object files:"
	@for file in $(OBJ); do echo "  $$file"; done