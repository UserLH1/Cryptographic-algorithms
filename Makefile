CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude

# Directorul unde punem artefactele de build
OBJDIR = dist/obj
BINDIR = dist/bin

# Fișiere sursă
SRC = main.c \
      src/aes_gcm.c \
      src/des_cfb.c \
      src/utils.c \
      src/rsa.c

# Transformăm .c -> .o, dar punem .o în OBJDIR
OBJ = $(SRC:%.c=$(OBJDIR)/%.o)

# Ținta principală
all: $(BINDIR)/crypto

$(BINDIR)/crypto: $(OBJ)
	mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

# Regula generică de compilare pentru fiecare .c
$(OBJDIR)/%.o: %.c
	mkdir -p $(dir $@)  # creează subfoldere, dacă există
	$(CC) $(CFLAGS) -c $< -o $@

# Curățare
clean:
	rm -rf dist