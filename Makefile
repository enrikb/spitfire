CFLAGS += -g -O2
LDFLAGS += -g

all: dragon ref/dragon-ref ref/dragon-opt

dragon: dragon.o
ref/dragon-ref: ref/dragon-ref.o ref/dragon.o ref/dragon-sboxes.o ref/ecrypt-sync.o
ref/dragon-opt: ref/dragon-opt.o ref/dragon.o ref/dragon-sboxes.o ref/ecrypt-sync.o

dragon.o: CFLAGS += -DDRAGON_TEST=1
dragon.o: dragon.c Makefile

# todo: header deps

clean:
	rm -f dragon dragon.o ref/dragon-ref ref/dragon-opt ref/*.o

.PHONY: all clean
