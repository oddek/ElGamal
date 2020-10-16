PROG = ElGamal
CC = g++
CPPFLAGS = -I /usr/include -L /usr/lib
LDFLAGS = -lgmp -lgmpxx

OBJS = src/main.o src/ElGamal.o
all: build run
run:
	./$(PROG)

build: $(PROG)

$(PROG): $(OBJS)
	g++ -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f *stackdump $(PROG) *.o .depend


