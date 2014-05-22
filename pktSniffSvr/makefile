# ultra simple
CC=gcc
CFLAGS=-c -Wall
# lpcap for BSD, libpcap-dev for Linux
CLIBS=-lpcap
CLINUXLIBS=
LDFLAGS=
SOURCES=svr.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pktsniffer

linux: $(SOURCES) $(EXECUTABLE)
	CLINUXLIBS=-llibpcap-dev


all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(CLIBS) $(CLINUXLIBS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf *.o $(EXECUTABLE)

