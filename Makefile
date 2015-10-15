ifndef PKGCONFIG
	PKGCONFIG = pkg-config
endif

CFLAGS = -std=c99 -Wall -pedantic `$(PKGCONFIG) --cflags --libs openssl`

EXT =

ifdef MINGW
	CFLAGS += -lgdi32
	EXT = .exe
endif

ifdef STATIC
	CFLAGS += -static
endif

.PHONY: all dbg clean

all: CFLAGS += -O3 -pipe
all:
	$(CC) -o keygen$(EXT) rsa.c rsagen.c $(CFLAGS)
	$(CC) -o decr$(EXT) decr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c $(CFLAGS)
	$(CC) -o encr$(EXT) encr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c $(CFLAGS)

dbg: CFLAGS += -O0 -g3
dbg:
	$(CC) $(CFLAGS) -o keygen rsa.c rsagen.c
	$(CC) $(CFLAGS) -o decr decr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c
	$(CC) $(CFLAGS) -o encr encr.c encrypt.c rsaoaep.c aescbc.c oaep.c rsa.c aes.c aes_lookup.c

clean:
	rm -f keygen decr encr *.exe
