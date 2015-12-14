SBINPATH = /usr/sbin
ETCPATH = /etc
INITPATH = /etc/rc.d/init.d

CFLAGS += $(DF_FLAGS)

CFLAGS += -I$(OS_LIB_PATH)/include -D__LINUX_OS_FC__
LDFLAGS += -L$(OS_LIB_PATH)/ -los -lpthread -lrt

OBJS = bpalogin.o protocol.o transaction.o gen_md5.o unixmain.o

bpalogin: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(OPTFLAGS) $(LDFLAGS) -o $@
	$(STRIP) $@
	@chmod 777 $@

.c.o:
	$(CC) -c $(LDFLAGS) $(CFLAGS) -o $@ $<
clean:
	rm -fr *.o 

pristine: clean
	rm -f bpalogin

$(OBJS): bpalogin.h
