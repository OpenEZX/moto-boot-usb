/* ezx_boot_usb - Ram Loader for Motorola EZX phones
 * (C) 2006 by Harald Welte <laforge@gnumonks.org>
 *
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
	int ret;

	memset(buf, 0, sizeof(buf));

	ret = usb_bulk_read(hdl, EZX_IN_EP, buf, sizeof(buf), 0);

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

	printf("TX: %s (%s)\n", buf,  hexdump(buf, cur));

	ret = usb_bulk_write(hdl, EZX_OUT_EP, buf, cur, 0);
	ezx_blob_recv_reply();
	return ret;
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

	if (size > 8192)
		return -1;

	*(u_int16_t *)buf = htons(size);
	memcpy(buf+2, data, size);
	buf[size+2] = ezx_csum(data, size);

	return ezx_blob_send_command("BIN", buf, size+3);
}

#define CHUNK_SIZE 512
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


int main(int argc, char **argv)
{
	struct usb_device *dev;
	char prog[1024*1024];

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

	ezx_blob_send_command("RQHW", NULL, 0);
	ezx_blob_load_program(0x0a0200000, prog, 256*1024);

	//ezx_blob_cmd_jump(0xa0200000);

	//ezx_blob_send_command("RQHW", NULL, 0);
	//ezx_blob_recv_reply();
	//ezx_blob_send_command("POWER_DOWN", NULL, 0);
	//ezx_blob_recv_reply();

	exit(0);
}
