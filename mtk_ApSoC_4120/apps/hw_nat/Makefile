EXEC = hw_nat acl ac mtr

HWNAT_OBJS = hw_nat.o hwnat_api.o util.o
AC_OBJS = ac.o ac_api.o util.o
ACL_OBJS = acl.o acl_api.o util.o
MTR_OBJS = mtr.o mtr_api.o util.o

CFLAGS += -I$(KERNELPATH)/net/nat/hw_nat
CFLAGS += -I$(KERNELPATH)/include/
all: $(EXEC)

hw_nat: $(HWNAT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(HWNAT_OBJS) 

acl: $(ACL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(ACL_OBJS) 

ac: $(AC_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(AC_OBJS) 

mtr: $(MTR_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(MTR_OBJS) 

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o



