SRC = ipping.c
OBJS=$(SRC:.c=.o) 

CFLAGS += -I$(OS_LIB_PATH)/include -DINCLUDE_IPPING_DIAG -D__LINUX_OS_FC__ -DCMM_MSG
LDFLAGS += -L$(OS_LIB_PATH) -los -lpthread -lrt

%.o: %.c
	$(CC) $(CFLAGS) -c  -o $@ $<

ipping: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) && $(STRIP)  ipping 
 
#ifeq ($(FULL_COMPILE), y)
#sinclude $(SRC:.c=.d)
#endif
 

#%.d: ./src/%.c
#	@$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
#	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
#	rm -f $@.$$$$
 
.PHONY: clean
clean:
	$(RM) $(OBJS) ipping
#$(SRC:.c=.d) 