# ultra simple
CC=gcc
CFLAGS=-c -Wall
CLIBS=-lpcap
LDFLAGS=
SOURCES=svr.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pktsniffer

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(CLIBS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf *.o $(EXECUTABLE)

