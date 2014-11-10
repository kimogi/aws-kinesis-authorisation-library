#root Makefile

export CC:=gcc
export LIBS := -lrt -lcurl -lcrypto -lm -l:libpcap.a

SUBDIRS = prop_tool kinesis

.PHONY: subdirs $(SUBDIRS) clean all

all: kinesis_utils 

subdirs: $(SUBDIRS)
     
$(SUBDIRS):
	$(MAKE) -C $@

utils.o : utils.c
   $(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) -c utils.c

kinesis_utils : kinesis prop_tool utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o kinesis_utils utils.o kinesis/kinesis_tool.o kinesis/crypto_tool.o kinesis/list.o kinesis/kinesis_signing.o prop_tool/prop.o $(LIBS)

clean:
	-rm -f kinesis_utils
	-rm -f *.o
	for d in $(SUBDIRS); do (cd $$d; $(MAKE) clean ); done
