OBJS = rtnetlink.o \
			 xalloc.o
LIBS = -lpcap

CFLAGS = -g
CFLAGS += $(LIBS)

main: $(clean) $(OBJS)
	gcc -o test $(OBJS) $(CFLAGS) 

gdb: $(OBJS)
	gcc -o test $(OBJS) $(CFLAGS) 

#%.o: %.c
#	gcc -g -o $@ -c $<

clean: 
	rm *.o test
