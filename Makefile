CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2 -D_GNU_SOURCE
LDFLAGS :=
LIBS    := -lssl -lcrypto -lresolv -lpthread  # -lcurl can be added later for RDAP convenience if headers available

SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
BIN     := i2

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Header dependencies (simple approach - any header change will cause full recompile of affected units)
HEADERS := $(wildcard $(INC_DIR)/*.h)

.PHONY: all clean run help rebuild

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)
	@echo "Built $(BIN)"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

rebuild: clean all

clean:
	rm -rf $(BUILD_DIR) $(BIN) *.md *.txt i2_*.md i2_*.txt

run: $(BIN)
	./$(BIN) https://example.com

help:
	@echo "i2 Makefile targets:"
	@echo "  make        - build the binary"
	@echo "  make run    - build + run against example.com"
	@echo "  make clean  - remove build artifacts and sample reports"
