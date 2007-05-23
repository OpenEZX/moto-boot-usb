/* ezx_boot_usb - Ram Loader for Motorola EZX phones
 *
 * (C) 2006 by Harald Welte <laforge@gnumonks.org>
 * (C) 2006 by Stefan Schmidt <stefan@datenfreihafen.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * CONTRIBUTORS:
 *  	Wang YongLai <dotmonkey@gmail.com>
 *  			ROKR E2 support
 *  	Daniel Ribeiro <drwyrm@gmail.com>
 *  			Added support for Blob2 boot on A780
 *  			Ramdisk upload support
 *
 */

/*
 * This program allows you to download executable code from the PC to the phone
 * RAM.  After downloading it, the code can be executed.
 *
 * In order to make this work, the phone must be running in the bootloader,
 * rather than the regular OS.  To achieve this, push both the jogdial button
 * and the photo button while pressing power-on (A780).
 *
 * A complete list how to enter the bootloader can be found here:
 * http://wiki.openezx.org/Bootloader
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <usb.h>

const char *
hexdump(const void *data, unsigned int len)
{
	static char string[65535];
	unsigned char *d = (unsigned char *) data;
	unsigned int i, left;

	string[0] = '\0';
	left = sizeof(string);
	for (i = 0; len--; i += 3) {
		if (i >= sizeof(string) -4)
			break;
		snprintf(string+i, 4, " %02x", *d++);
	}
	return string;
}

struct phonetype {
	char *name;
	u_int16_t product_id;
	u_int8_t out_ep;
	u_int8_t in_ep;
	u_int32_t kernel_addr;
	u_int32_t ramdisk_addr;
	u_int32_t reserved; /* for kernel parameters */
};

#define EZX_VENDOR_ID 0x22b8
struct phonetype phonetypes[] = {
	{ "A780/E680",		0x6003, 0x02, 0x81, 0xa0200000, 0xa0400000, 0 },
	{ "A780/E680 Blob2",	0x6021, 0x02, 0x81, 0xa0300000, 0xa0500000, 0 },
	{ "E2/A1200/E6",	0x6023, 0x02, 0x82, 0xa0de0000, /*FIXME*/0, 0 },

	{ "Unknown",		0x0000, 0x00, 0x00, 0x00000000, 0x00000000, 0 }
};

#define NUL	0x00
#define STX	0x02
#define	ETX	0x03
#define	RS	0x1E

struct phonetype phone = { "Unknown", 0, 0, 0, 0, 0, 0 };

static struct usb_dev_handle *hdl;
static struct usb_device *find_ezx_device(void)
{
	struct usb_bus *bus;

	for (bus = usb_busses; bus; bus = bus->next) {
		struct usb_device *dev;
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == EZX_VENDOR_ID)
			{
				int n;
				for (n=0;phonetypes[n].product_id!=0;n++) {
					if (dev->descriptor.idProduct == phonetypes[n].product_id)
						phone = phonetypes[n];
				}
				if (phone.product_id == 0)
					return NULL;
				printf("%s found.\n", phone.name);
			}
			if (dev->descriptor.iManufacturer == 1
			    && dev->descriptor.iProduct == 2
			    && dev->descriptor.bNumConfigurations == 1
			    && dev->config->bNumInterfaces == 1
			    && (dev->config->iConfiguration == 4 || dev->config->iConfiguration == 5)) 
				return dev;
		}
	}
	return NULL;
}

static int ezx_blob_recv_reply(void)
{
	char buf[8192];
	int ret, i;

	memset(buf, 0, sizeof(buf));

	ret = usb_bulk_read(hdl, phone.in_ep, buf, sizeof(buf), 0);

	for (i = 0; i < ret; i ++)
		if (buf[i] == 0x03)
			buf[i] = 0x00;

	printf("RX: %s (%s)\n", buf, hexdump(buf, ret));

	return ret;
}


static int ezx_blob_send_command(char *command, char *payload, int len)
{
	char buf[8192];
	int cmdlen = strlen(command);
	int cur = 0;
	int ret;

	memset(buf, 0, sizeof(buf));

	buf[cur++] = STX;
	memcpy(&buf[cur], command, cmdlen);
	cur += cmdlen;

	if (payload) {
		buf[cur++] = RS;
		memcpy(&buf[cur], payload, len);
		cur += len;
	}
	buf[cur++] = ETX;
	//buf[cur++] = NUL;

	if (!strcasecmp(command, "bin"))
		printf("TX: %u bytes\n", cur);
	else
		printf("TX: %s (%s)\n", buf,  hexdump(buf, cur));

	ret = usb_bulk_write(hdl, phone.out_ep, buf, cur, 0);
	if (ret < 0)
		return ret;

	/* this usleep is required in order to make the process work.
	 * apparently some race condition in the bootloader if we feed
	 * data too fast */
	usleep(5000);

	return ezx_blob_recv_reply();
}

/* the most secure checksum I've ever seen ;) */
static u_int8_t ezx_csum(char *data, int len)
{
	u_int8_t ret = 0;
	int i;

	for (i = 0; i < len; i++)
		ret += data[i];

	return ret;
}

static int ezx_blob_cmd_addr(u_int32_t addr)
{
	char buf[128];
	u_int8_t csum;
	int len;

	len = snprintf(buf, sizeof(buf), "%8X", addr);
	csum = ezx_csum(buf, 8);
	len += snprintf(buf+8, sizeof(buf)-len, "%2X", csum);

	if (len != 10)
		return -1;

	return ezx_blob_send_command("ADDR", buf, len);
}

static int ezx_blob_cmd_jump(u_int32_t addr)
{
	char buf[128];
	u_int8_t csum;
	int len;

	len = snprintf(buf, sizeof(buf), "%8X", addr);
	csum = ezx_csum(buf, 8);
	len += snprintf(buf+8, sizeof(buf)-len, "%2X", csum);

	if (len != 10)
		return -1;

	return ezx_blob_send_command("JUMP", buf, len);
}

static int ezx_blob_cmd_bin(char *data, u_int16_t size)
{
	char buf[8192+2+1];
//	u_int8_t csum;
	int rem = size % 8;

/* FIXME: Any difference between (8 - rem) and rem here? */
	if (rem)
		size += (8 - rem);
//		size += rem;

	if (size > 8192)
		return -1;

	memset(buf, 0, sizeof(buf));

	*(u_int16_t *)buf = htons(size);
	memcpy(buf+2, data, size);
	buf[size+2] = ezx_csum(data, size);

	return ezx_blob_send_command("BIN", buf, size+3);
}

#define CHUNK_SIZE 4096
static int ezx_blob_load_program(u_int32_t addr, char *data, int size)
{
	u_int32_t cur_addr;
	char *cur_data;

	if(!addr) {
		printf("No load address defined\n");
		return -1;
	}

	for (cur_addr = addr, cur_data = data; 
	     cur_addr < addr+size; 
	     cur_addr += CHUNK_SIZE, cur_data += CHUNK_SIZE) {
		int remain = (data + size) - cur_data;
		if (remain > CHUNK_SIZE)
			remain = CHUNK_SIZE;

		if (ezx_blob_cmd_addr(cur_addr) < 0)
			break;
		if (ezx_blob_cmd_bin(cur_data, remain) < 0)
			break;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct usb_device *dev;
	char *prog;
	struct stat st;
	int fd;

	usb_init();
	if (!usb_find_busses())
		exit(1);
	if (!usb_find_devices())
		exit(1);

	dev = find_ezx_device();
	if (!dev) {
		printf("Cannot find EZX device in bootloader mode\n");
		exit(1);
	}

	if (argc < 2) {
		printf("usage: %s <kernel> [ramdisk]\n", argv[0]);
		exit(2);
	}

	hdl = usb_open(dev);
	if (!hdl) {
		printf("Unable to open usb device: %s\n", usb_strerror());
		exit(1);
	}

	if (usb_claim_interface(hdl, 0) < 0) {
		printf("Unable to claim usb interface 1 of device: %s\n", usb_strerror());
		exit(1);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		exit(2);

	if (fstat(fd, &st) < 0) {
		printf("Error to access file `%s': %s\n", argv[1], strerror(errno));
		exit(2);
	}

	/* mmap kernel image passed as parameter */
	prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!prog)
		exit(1);
	
	ezx_blob_send_command("RQSN", NULL, 0);
	ezx_blob_send_command("RQVN", NULL, 0);
	ezx_blob_load_program(phone.kernel_addr, prog, st.st_size);

	munmap(prog, st.st_size);
	close(fd);
	prog = NULL;

	/* Send ramdisk */
	if (argc > 2) {
		fd = open(argv[2], O_RDONLY);
		if (fd < 0 || fstat(fd, &st) < 0)
			printf("File error (%s): %s\n", argv[2], strerror(errno));
		else
			prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (prog) {
			ezx_blob_load_program(phone.ramdisk_addr, prog, st.st_size);
			munmap(prog, st.st_size);
		}
		if(fd) close(fd);
		prog = NULL;
	}

	ezx_blob_cmd_jump(phone.kernel_addr);
	//ezx_blob_send_command("POWER_DOWN", NULL, 0);
	//ezx_blob_recv_reply();

	exit(0);
}
