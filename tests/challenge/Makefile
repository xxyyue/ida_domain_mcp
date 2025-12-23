CC      ?= gcc
CFLAGS  ?= -O2 -fno-plt -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now

SRC_DIR := src
TOOLS   := tools
BIN_DIR := binaries

FLAG ?= FLAG{dual_binary_static_analysis}

all: clean prepare $(BIN_DIR)/secure_check.so $(BIN_DIR)/device_main

prepare:
	mkdir -p $(BIN_DIR)
	python3 $(TOOLS)/gen_target.py --flag '$(FLAG)' --out $(SRC_DIR)/target_blob.h

$(BIN_DIR)/secure_check.so: $(SRC_DIR)/secure_check.c $(SRC_DIR)/secure_check.h $(SRC_DIR)/target_blob.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(SRC_DIR)/secure_check.c $(LDFLAGS)
	strip -s $@ || true

$(BIN_DIR)/device_main: $(SRC_DIR)/device_main.c
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/device_main.c -ldl $(LDFLAGS)
	strip -s $@ || true

run: all
	cd $(BIN_DIR) && ./device_main

clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/target_blob.h

.PHONY: all clean prepare run
