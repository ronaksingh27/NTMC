# Compiler
CC = gcc

# Directories (Fix the space issue by using quotes)
SRC_DIR = utility
ECC_DIR = ECC
AUTH_DIR = AUTH\ AND\ KEY\ ESTB
HEADERS_DIR = headers

# Compiler Flags
CFLAGS = -I$(HEADERS_DIR)

# Libraries
LIBS = -lgmp -lssl -lcrypto

# Source Files (Common)
COMMON_SRCS = $(SRC_DIR)/ecc_utility.c $(SRC_DIR)/encrypt_utility.c $(SRC_DIR)/hash_utility.c

# Source Files for Different Programs
ECC_SRCS = $(ECC_DIR)/ecc.c $(COMMON_SRCS)
PARTA_SRCS = $(AUTH_DIR)/partA.c $(COMMON_SRCS)

# Output Executables
ECC_TARGET = ecc_program
PARTA_TARGET = partA_program

# Default Rule (Compiles both)
all: $(ECC_TARGET) $(PARTA_TARGET)

# Compile ECC Program
$(ECC_TARGET): $(ECC_SRCS)
	$(CC) $(CFLAGS) -o $(ECC_TARGET) $(ECC_SRCS) $(LIBS)

# Compile PartA Program
$(PARTA_TARGET): $(PARTA_SRCS)
	$(CC) $(CFLAGS) -o $(PARTA_TARGET) $(PARTA_SRCS) $(LIBS)

# Clean Rule
clean:
	rm -f $(ECC_TARGET) $(PARTA_TARGET)
