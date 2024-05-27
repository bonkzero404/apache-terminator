MODULE_NAME = mod_redsec_terminator

SRC_FILES = mod_redsec_terminator.c util.c body_reader.c json_reader.c

OUTPUT_FILE = $(MODULE_NAME).so

CC = gcc
CFLAGS = -std=c17 -fPIC -Wall -I/usr/include/httpd -I/usr/include/apr-1 -I/usr/include/apr-util-1 -I/usr/include/json-c
LDFLAGS = -shared -ljson-c

APXS = apxs

all: $(OUTPUT_FILE)

$(OUTPUT_FILE): $(SRC_FILES)
	$(APXS) -i -a -n $(MODULE_NAME) -c $(SRC_FILES) $(LDFLAGS)

clean:
	rm -rf .libs
	rm -f *.o *.la *.lo *.slo

.PHONY: all clean
