#!/usr/bin/make
LDFLAGS=-lusb

all: boot_usb

clean:
	-rm -f *.o boot_usb

boot_usb: boot_usb.o
	$(CC) $(LDFLAGS) -o $@ $<

boot_usb.o: boot_usb.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONEY: all clean
