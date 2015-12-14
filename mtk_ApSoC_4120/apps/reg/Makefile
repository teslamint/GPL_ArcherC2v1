EXEC = reg
OBJS = reg.o
CFLAGS += -I$(KERNELPATH)/drivers/net/rt_rdm -I$(KERNELPATH)/include

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

