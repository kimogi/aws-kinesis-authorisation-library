#kinesis Makefile

.PHONY: all clean

all: kinesis_tool.o crypto_tool.o list.o kinesis_signing.o

kinesis_tool.o: kinesis_tool.c kinesis_tool.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c kinesis_tool.c

crypto_tool.o : crypto_tool.c crypto_tool.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c crypto_tool.c

list.o : list.c list.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c list.c

kinesis_signing.o : kinesis_signing.c kinesis_signing.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c kinesis_signing.c

clean :
	-rm -f *.o
