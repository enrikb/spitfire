CFLAGS += -g -O0 -DDRAGON_TEST=1

dragon: dragon.o

dragon.o: dragon.c Makefile

clean:
	rm -f dragon dragon.o

.PHONY: clean
