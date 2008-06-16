/* ezx_boot_usb - Ram Loader for Motorola EZX phones
 *
 * (C) 2006 by Harald Welte <laforge@gnumonks.org>
 * (C) 2006, 2008 by Stefan Schmidt <stefan@datenfreihafen.org>
 * Copyright (C) 2007  Daniel Ribeiro <drwyrm@gmail.com>
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
 *	Wang YongLai <dotmonkey@gmail.com>
 *			ROKR E2 support
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

#include <asm-arm/setup.h> /* for boot_params */

//#define DEBUG

#define info(format, arg...) \
	printf(format, ##arg); fflush(stdout)

#ifdef DEBUG
#define dbg(format, arg...) \
	printf(format "\n", ## arg)
#else
#define dbg(format, arg...)
#endif

#ifdef DEBUG
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
#endif

struct phonetype {
	char *name;
	u_int16_t product_id;
	u_int8_t out_ep;
	u_int8_t in_ep;
	u_int32_t kernel_addr;
	u_int32_t initrd_addr;
	u_int32_t params_addr;
	char *code;
	int code_size;
};

/* We set set the machine ID from boot_usb with this assembler tricks beacuse
 * the original blob is not able to do this for us.
 *
 * ldr     r1, [pc, #8]
 * sub     r0, pc, #12
 * add     r0, r0, #4096
 * mov     pc, r0
 */
#define pxa_code "\x08\x10\x9F\xE5\x0C\x00\x4F\xE2\x01\x0A\x80\xE2\x00\xF0\xA0\xE1"
#define pxa_code_s 16

#define EZX_VENDOR_ID 0x22b8
struct phonetype phonetypes[] = {
{ "A780/E680",        0x6003, 0x02, 0x81, 0xa0200000, 0xa0400000, 0xa0000100, pxa_code, pxa_code_s },
{ "Generic Blob",     0xbeef, 0x02, 0x81, 0xa0200000, 0xa0400000, 0xa0000100, pxa_code, pxa_code_s }, /* pxa_code is temporary here */
{ "A780/E680 Blob2",  0x6021, 0x02, 0x81, 0xa0300000, 0xa0400000, 0xa0000100, pxa_code, pxa_code_s },
{ "E2/A1200/E6/A910", 0x6023, 0x01, 0x82, 0xa0de0000, /*FIXME*/0, /*FIXME*/0, pxa_code, pxa_code_s },
{ "RAZR2 V8",         0x6403, 0x01, 0x82, 0xa0de0000, /*FIXME*/0, /*FIXME*/0, NULL, 0 },
{ "Unknown",          0x0000, 0x00, 0x00, 0x00000000, 0x00000000, 0x00000000, NULL,	0 }
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

	info("Serching for EZX phone: ");
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
				if (phone.product_id == 0) {
					info("Unknown EZX phone (%04x).\n",
						dev->descriptor.idProduct);
					return NULL;
				}
				info("%s found.\n", phone.name);
				return dev;
			}
		}
	}
	info("none.\n");
	return NULL;
}

static int ezx_blob_recv_reply(void)
{
	char buf[8192];
	int ret, i;

	memset(buf, 0, sizeof(buf));

	ret = usb_bulk_read(hdl, phone.in_ep, buf, sizeof(buf), 0);

	for (i = 0; i < ret; i++)
		if (buf[i] == 0x03)
			buf[i] = 0x00;

	dbg("RX: %s (%s)", buf, hexdump(buf, ret));

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
#ifdef DEBUG
	if (!strcasecmp(command, "bin"))
		dbg("TX: %u bytes", cur);
	else
		dbg("TX: %s (%s)", buf,  hexdump(buf, cur));
#endif
	ret = usb_bulk_write(hdl, phone.out_ep, buf, cur, 0);
	if (ret < 0)
		return ret;

	/* this usleep is required in order to make the process work.
	 * apparently some race condition in the bootloader if we feed
	 * data too fast
	 */
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
	int rem = size % 8;

	if (rem) {
		size += rem;
	}

	if (size > 8192)
		return -1;

	memset(buf, 0, sizeof(buf));

	*(u_int16_t *)buf = htons(size);
	memcpy(buf+2, data, size);
	buf[size+2] = ezx_csum(data, size);

	return ezx_blob_send_command("BIN", buf, size+3);
}

#define CHUNK_SIZE 4096
static int ezx_blob_load_program(u_int16_t phone_id, u_int32_t addr, char *data, int size)
{
	u_int32_t cur_addr;
	char *cur_data;
	int err;

	if(!addr) /* workaround for missing values */
		return -1;

	for (cur_addr = addr, cur_data = data;
	     cur_addr < addr+size;
	     cur_addr += CHUNK_SIZE, cur_data += CHUNK_SIZE) {
		int remain;
		if (phone_id == 0x6023) /* A1200 needs a fixed chunk size*/
			remain = 4096;
		else
			remain = (data + size) - cur_data;
		if (remain > CHUNK_SIZE)
			remain = CHUNK_SIZE;

		if ((err = ezx_blob_cmd_addr(cur_addr)) < 0)
			break;
		if ((err = ezx_blob_cmd_bin(cur_data, remain)) < 0)
			break;
		info("\b\b\b%02d%%",(int)((100*(cur_data-data))/size));
	}
	if (err < 0) return err;
	info("\b\b\b\b100%% OK\n");
	return 0;
}

#define error(format, arg...) \
	sprintf(serror, format, ##arg)
int main(int argc, char *argv[])
{
	struct usb_device *dev;
	char *prog;
	struct stat st;
	int fd;
	char serror[1024];
	struct tag *tag;
	struct tag *first_tag;
	int tagsize;
	char *asm_code;
	int k_offset = 0;
	int mach_id = 867; /* 867 is the old EZX mach id */

	usb_init();
	if (!usb_find_busses())
		exit(1);
	if (!usb_find_devices())
		exit(1);

	dev = find_ezx_device();
	if (!dev) {
		error("cannot find known EZX device in bootloader mode");
		goto exit;
	}
	if (argc < 2) {
		error("usage: %s <kernel> [machid] [cmdline] [initrd]", argv[0]);
		goto exit;
	}
	if (!(hdl = usb_open(dev))) {
		error("open usb device: %s", usb_strerror());
		goto exit;
	}
	if (usb_claim_interface(hdl, 0) < 0) {
		error("claim usb interface 1 of device: %s", usb_strerror());
		goto exit;
	}
	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		error("%s: %s", argv[1], strerror(errno));
		goto poweroff;
	}
	if (fstat(fd, &st) < 0) {
		error("%s: %s", argv[1], strerror(errno));
		goto poweroff;
	}
	/* mmap kernel image passed as parameter */
	if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
		error("mmap error: %s", strerror(errno));
		goto poweroff;
	}

//#ifdef DEBUG /* query information only if debugging */
	if (ezx_blob_send_command("RQSN", NULL, 0) < 0) {
		error("RQSN");
		goto poweroff;
	}
	if (ezx_blob_send_command("RQVN", NULL, 0) < 0) {
		error("RQVN");
		goto poweroff;
	}
//#endif
	if (argc >=3)
		mach_id = atoi(argv[2]);

	if (phone.code_size > 0 && mach_id > 0) {
		info("Sending mach id code %d:     ", mach_id);
		if ((asm_code = malloc(CHUNK_SIZE)) == NULL) {
			error("failed to alloc memory");
			goto poweroff;
		}
		memset(asm_code, 0, sizeof(asm_code));
		memcpy(asm_code, phone.code, phone.code_size);
		*(u_int32_t *)(asm_code+phone.code_size) = mach_id;

		if (ezx_blob_load_program(phone.product_id, phone.kernel_addr, asm_code, CHUNK_SIZE) < 0) {
			error("asm code send failed");
			goto poweroff;
		}
		k_offset += 4096;
	}

	info("Uploading kernel:     ");
	if (ezx_blob_load_program(phone.product_id, phone.kernel_addr+k_offset, prog, st.st_size) < 0) {
		error("kernel upload failed");
		goto poweroff;
	}

	munmap(prog, st.st_size);
	close(fd);
	prog = NULL;

	if (argc < 4)
		goto run_kernel;

	/* send boot_params */
	if (argc >= 5)		/* with initrd - 4 tags */
		tagsize = sizeof(struct tag_header) * 4 +
					sizeof(struct tag_initrd);
	else			/* cmdline only - 3 tags */
		tagsize = sizeof(struct tag_header) * 3;
	/* cmdline string */
	tagsize += (strlen(argv[3]) > COMMAND_LINE_SIZE ? COMMAND_LINE_SIZE :
		strlen(argv[3])) + 5;

	if (!(tag = malloc(tagsize))) {
		error("cannot alloc %d bytes for params", tagsize);
		goto poweroff;
	}
	first_tag = tag;

	tag->hdr.tag = ATAG_CORE;
	tag->hdr.size = tag_size(tag_core);
	tag->u.core.flags = 0;
	tag->u.core.pagesize = 0;
	tag->u.core.rootdev = 0;

	tag = tag_next(tag);
	tag->hdr.tag = ATAG_CMDLINE;
	tag->hdr.size = ((sizeof(struct tag_header) +
				strlen(argv[3]) + 5) >> 2);
	strncpy(tag->u.cmdline.cmdline, argv[3], COMMAND_LINE_SIZE);

	if (argc < 5)
		goto send_params;

	/* Send initrd */
	fd = open(argv[4], O_RDONLY);
	if (fd < 0 || fstat(fd, &st) < 0) {
		error("%s: %s", argv[4], strerror(errno));
		goto poweroff;
	}
	if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
		error("mmap error: %s", strerror(errno));
		goto poweroff;
	}
	info("Uploading initrd:     ");
	if (ezx_blob_load_program(phone.product_id, phone.initrd_addr, prog, st.st_size) < 0) {
		error("initrd upload failed");
		goto poweroff;
	}

	tag = tag_next(tag);
	tag->hdr.tag = ATAG_INITRD2;
	tag->hdr.size = tag_size(tag_initrd);
	tag->u.initrd.start = phone.initrd_addr;
	tag->u.initrd.size = st.st_size;
	munmap(prog, st.st_size);
	close(fd);
	prog = NULL;

send_params:
	tag = tag_next(tag);
	tag->hdr.tag = ATAG_NONE;
	tag->hdr.size = 0;
	info ("Uploading params:     ");
	if (ezx_blob_load_program(phone.product_id, phone.params_addr, (void *) first_tag, tagsize) < 0) {
		error("params upload failed");
		goto poweroff;
	}
run_kernel:
	info("Calling the kernel...\n");
	if (ezx_blob_cmd_jump(phone.kernel_addr) < 0) {
		error("kernel jump failed");
		goto poweroff;
	}
	info("DONE\n");
	exit(0);
poweroff:
	/* this just lock-up blob */
//	ezx_blob_send_command("POWER_DOWN", NULL, 0);
exit:
	info("FAILED: %s\n", serror);
	exit(1);
}
