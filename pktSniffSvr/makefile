# ultra simple
CC=gcc
CFLAGS=-c -Wall
# lpcap for BSD, libpcap-dev for Linux
CLIBS=-lpcap
CLINLIBS=-lpcap
LDFLAGS=
SOURCES=svr.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=pktsniffer

all: $(SOURCES) $(EXECUTABLE)


linux: $(SOURCES) $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(CLINLIBS)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(CLIBS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf *.o $(EXECUTABLE) linux

