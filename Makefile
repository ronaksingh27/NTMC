# Compiler
CC = gcc

# Directories (Fix the space issue by using quotes)
SRC_DIR = utility
SM_Setup_DIR = SM_Setup
AUTH_DIR = AUTH\ AND\ KEY\ ESTB
HEADERS_DIR = headers

# Compiler Flags
CFLAGS = -I$(HEADERS_DIR)

# Libraries
LIBS = -lgmp -lssl -lcrypto

# Source Files (Common)
COMMON_SRCS = $(SRC_DIR)/ecc_tility.c $(SRC_DIR)/encrypt_utility.c $(SRC_DIR)/hash_utility.c

# Source Files for Different Programs
SM_Setup_SRCS = $(SM_Setup_DIR)/main.c $(COMMON_SRCS)
PARTA_SRCS = $(AUTH_DIR)/partA.c $(COMMON_SRCS)

# Output Executables
SM_Setup_TARGET = SM_Setup_program
PARTA_TARGET = partA_program

# Default Rule (Compiles both)
all: $(SM_Setup_TARGET) $(PARTA_TARGET)

# Compile SM_Setup Program
$(SM_Setup_TARGET): $(SM_Setup_SRCS)
	$(CC) $(CFLAGS) -o $(SM_Setup_TARGET) $(SM_Setup_SRCS) $(LIBS)

# Compile PartA Program
$(PARTA_TARGET): $(PARTA_SRCS)
	$(CC) $(CFLAGS) -o $(PARTA_TARGET) $(PARTA_SRCS) $(LIBS)

# Clean Rule
clean:
	rm -f $(SM_Setup_TARGET) $(PARTA_TARGET)
