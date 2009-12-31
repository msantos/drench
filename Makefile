LIBNET_CONFIG=libnet-config

GCC=gcc
RM=/bin/rm
APP=drench
LDFLAGS=-L/usr/pkg/lib
CFLAGS=-I/usr/pkg/include -m32
LIBS=-lpcap -lcrypto


drench:
	$(GCC) $(LDFLAGS) $(CFLAGS) $(LIBS) \
		`$(LIBNET_CONFIG) --libs` \
		`$(LIBNET_CONFIG) --cflags` \
		`$(LIBNET_CONFIG) --defines` \
		-g -Wall -o $(APP) $(APP).c $(APP)_send.c $(APP)_arp.c 

clean:
	-@$(RM) $(APP)
