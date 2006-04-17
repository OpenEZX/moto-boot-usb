/* ezx_boot_usb - Ram Loader for Motorola EZX phones
 * (C) 2006 by Harald Welte <laforge@gnumonks.org>
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
 */

/*
 * This program allows you to download executable code from the PC to the phone
 * RAM.  After downloading it, the code can be executed.
 *
 * In order to make this work, the phone must be running in the bootloader, rather
 * than the regular OS.  To achieve this, push both the jogdial button and the
 * photo button while pressing power-on (A780).
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

#define EZX_VENDOR_ID	0x22b8
#define EZX_PRODUCT_ID	0x6003
#define EZX_OUT_EP	0x02
#define EZX_IN_EP	0x81

#define NUL	0x00
#define STX	0x02
#define	ETX	0x03
#define	RS	0x1E

static struct usb_dev_handle *hdl;
static struct usb_device *find_ezx_device(void)
{
	struct usb_bus *bus;

	for (bus = usb_busses; bus; bus = bus->next) {
		struct usb_device *dev;
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == EZX_VENDOR_ID
			    && dev->descriptor.idProduct == EZX_PRODUCT_ID
			    && dev->descriptor.iManufacturer == 1
			    && dev->descriptor.iProduct == 2
			    && dev->descriptor.bNumConfigurations == 1
			    && dev->config->bNumInterfaces == 1
			    && dev->config->iConfiguration == 5)
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

	ret = usb_bulk_read(hdl, EZX_IN_EP, buf, sizeof(buf), 0);

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

	ret = usb_bulk_write(hdl, EZX_OUT_EP, buf, cur, 0);
	if (ret < 0)
		return ret;

	/* this usleep is required in order to make the process work.
	 * apparently some race condition in the bootloader if we feed
	 * data too fast */
	usleep(25000);

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
	u_int8_t csum;
	int rem = size % 8;

	if (rem)
		size += rem;

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
}

static struct option opts[] = {
	{ "load", 1, 0, 'l' },
	{ "exec", 0, 0, 'e' },
	{ "off", 0, 0, 'o' },
	{ 0, 0, 0, 0 },
};

#define KERNEL_RAM_BASE	0xA0200000


int main(int argc, char **argv)
{
	struct usb_device *dev;
	char *filename, *prog;
	struct stat st;
	int fd;
	u_int32_t word = 0x7c7c7c7c;

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

	hdl = usb_open(dev);
	if (!hdl) {
		printf("Unable to open usb device: %s\n", usb_strerror());
		exit(1);
	}

	if (usb_claim_interface(hdl, 0) < 0) {
		printf("Unable to claim usb interface 1 of device: %s\n", usb_strerror());
		exit(1);
	}

	filename = argv[1];
	if (!filename) {
		printf("You have to specify the file you want to flash\n");
		exit(2);
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		exit(2);

	if (fstat(fd, &st) < 0) {
		printf("Error to access file `%s': %s\n", filename, strerror(errno));
		exit(2);
	}

	/* mmap kernel image passed as parameter */
	prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!prog)
		exit(1);

	//ezx_blob_send_command("RQHW", NULL, 0);

#if 0
	/* doesn't work because of address restrictions */
	ezx_blob_cmd_addr(0xa000000);
	ezx_blob_cmd_bin(&word, 4);
#endif

	ezx_blob_load_program(KERNEL_RAM_BASE, prog, st.st_size);

	ezx_blob_cmd_jump(KERNEL_RAM_BASE);

	//ezx_blob_send_command("RQHW", NULL, 0);
	//ezx_blob_recv_reply();
	//ezx_blob_send_command("POWER_DOWN", NULL, 0);
	//ezx_blob_recv_reply();

	exit(0);
}
