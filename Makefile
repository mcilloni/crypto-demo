ifndef PKGCONFIG
	PKGCONFIG = pkg-config
endif

CFLAGS = -std=c99 -Wall -pedantic `$(PKGCONFIG) --cflags --libs libcrypto`

.PHONY: all dbg clean

all: CFLAGS += -O3 -pipe
all:
	$(CC) $(CFLAGS) -o keygen rsa.c rsagen.c
	$(CC) $(CFLAGS) -o decr decr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c
	$(CC) $(CFLAGS) -o encr encr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c

dbg: CFLAGS += -O0 -g3
dbg:
	$(CC) $(CFLAGS) -o keygen rsa.c rsagen.c
	$(CC) $(CFLAGS) -o decr decr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c
	$(CC) $(CFLAGS) -o encr encr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c

clean:
	rm -f keygen decr encr
