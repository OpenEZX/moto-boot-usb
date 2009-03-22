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
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <usb.h>

#include <asm/setup.h> /* for boot_params */

//#define DEBUG

#define info(...) do {\
		printf(__VA_ARGS__); \
		fflush(stdout); \
	} while(0)

#define error(...) do {\
		fprintf(stderr, "FAILED: " __VA_ARGS__); \
		fprintf(stderr, "\n"); \
		fflush(stderr); \
	} while(0)

#ifdef DEBUG
#define dbg(...) do {\
		printf(__VA_ARGS__); \
		printf("\n"); \
		fflush(stdout); \
	} while(0)
#else
#define dbg(...)
#endif

#ifdef DEBUG
const char *hexdump(const void *data, unsigned int len)
{
	static char string[65535];
	unsigned char *d = (unsigned char *)data;
	unsigned int i, left;

	string[0] = '\0';
	left = sizeof(string);
	for (i = 0; len--; i += 3) {
		if (i >= sizeof(string) - 4)
			break;
		snprintf(string + i, 4, " %02x", *d++);
	}
	return string;
}
#endif

struct phonetype {
	const char *name;
	u_int16_t product_id;
	u_int8_t out_ep;
	u_int8_t in_ep;
	u_int32_t kernel_addr;
	u_int32_t initrd_addr;
	u_int32_t params_addr;
	const char *code;
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
{ "Unknown",          0x0000, 0x00, 0x00, 0x00000000, 0x00000000, 0x00000000, NULL, 0 }
};

#define NUL	0x00
#define STX	0x02
#define	ETX	0x03
#define	RS	0x1E

struct phonetype phone = { "Unknown", 0, 0, 0, 0, 0, 0, NULL, 0 };


/* usb handling */

#define USB_TIMEOUT 5000
static struct usb_dev_handle *hdl = NULL;

static struct usb_device *find_ezx_device(void)
{
	struct usb_bus *bus;

	info("Serching for EZX phone: ");
	for (bus = usb_busses; bus; bus = bus->next) {
		struct usb_device *dev;
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor == EZX_VENDOR_ID) {
				int n;
				for (n = 0; phonetypes[n].product_id != 0; n++) {
					if (dev->descriptor.idProduct ==
							phonetypes[n].product_id)
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

static void ezx_device_close(void)
{
	if (hdl != NULL) {
		usb_close(hdl);
		hdl = NULL;
	}
}

static void ezx_device_open()
{
	struct usb_device *dev;

	usb_init();
	if (!usb_find_busses())
		exit(1);
	if (!usb_find_devices())
		exit(1);

	dev = find_ezx_device();
	if (!dev) {
		error("cannot find known EZX device in bootloader mode");
		exit(1);
	}
	if (!(hdl = usb_open(dev))) {
		error("open usb device: %s", usb_strerror());
		exit(1);
	}

	/* Remember to close the device at exit */
	atexit(ezx_device_close);

	if (usb_claim_interface(hdl, 0) < 0) {
		error("claim usb interface 0 of device: %s", usb_strerror());
		exit(1);
	}
}



/* Blob commands */

static int ezx_blob_recv_reply(char *b)
{
	char buf[8192];
	int ret;

	memset(buf, 0, sizeof(buf));

	ret = usb_bulk_read(hdl, phone.in_ep, buf, sizeof(buf), 0);

	dbg("RX: %s", hexdump(buf, ret));

	if (b)
		memcpy(b, buf, 8192);

	if (buf[1] == 0x45 && buf[2] == 0x52 && buf[3] == 0x52)
		ret = -buf[5];

	return ret;
}

static int ezx_blob_send_command(const char *command, char *payload, int len, char *reply)
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
		dbg("TX: %s (%s)", buf, hexdump(buf, cur));
#endif

	ret = usb_bulk_write(hdl, phone.out_ep, buf, cur, 0);
	if (ret < 0)
		return ret;

	/* this usleep is required in order to make the process work.
	 * apparently some race condition in the bootloader if we feed
	 * data too fast
	 */
	/*
	usleep(USB_TIMEOUT);
	*/

	return ezx_blob_recv_reply(reply);
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

	len = snprintf(buf, sizeof(buf), "%08X", addr);
	csum = ezx_csum(buf, 8);
	len += snprintf(buf + 8, sizeof(buf) - len, "%02X", csum);

	if (len != 10)
		return -1;

	return ezx_blob_send_command("ADDR", buf, len, NULL);
}

static int ezx_blob_cmd_jump(u_int32_t addr)
{
	char buf[128];
	u_int8_t csum;
	int len;

	len = snprintf(buf, sizeof(buf), "%08X", addr);
	csum = ezx_csum(buf, 8);
	len += snprintf(buf + 8, sizeof(buf) - len, "%02X", csum);

	if (len != 10)
		return -1;

	return ezx_blob_send_command("JUMP", buf, len, NULL);
}

static int ezx_blob_cmd_rbin(u_int32_t addr, u_int16_t size, char *response)
{
	char buf[128];
	char reply[8192];
	u_int8_t *data;
	u_int8_t csum;
	int len, i;
	int err;

	len = snprintf(buf, sizeof(buf), "%08X%04X", addr, size);
	csum = ezx_csum(buf, 12);
	len += snprintf(buf + 12, sizeof(buf) - len, "%02X", csum);

	if (len != 14)
		return -1;

	err = ezx_blob_send_command("RBIN", buf, len, reply);

	if (err < 0)
		return err;

	csum = 0;
	data = reply + 6;
	for (i = 0; i < size; i++) {
		response[i] = data[i];
		csum += data[i];
	}

	if (csum != data[i])
		return -1;

	return 0;
}

static int ezx_blob_cmd_bin(char *data, u_int16_t size)
{
	char buf[8192 + 2 + 1];

	size += (size % 8) ? (8 - (size % 8)) : 0;

	if (size > 8192)
		return -1;

	memset(buf, 0, sizeof(buf));

	*(u_int16_t *)buf = htons(size);
	memcpy(buf + 2, data, size);
	buf[size + 2] = ezx_csum(data, size);

	return ezx_blob_send_command("BIN", buf, size + 3, NULL);
}

static int ezx_blob_cmd_flash(u_int32_t source, u_int32_t dest, u_int32_t size)
{
	char buf[128];
	u_int8_t csum;
	int len;

	len = snprintf(buf, sizeof(buf), "%08X", source);
	len += snprintf(buf + 8, sizeof(buf) - len, "%08X", dest);
	len += snprintf(buf + 16, sizeof(buf) - len, "%08X", size);
	csum = ezx_csum(buf, 24);
	len += snprintf(buf + 24, sizeof(buf) - len, "%02X", csum);

	if (len != 26)
		return -1;

	return ezx_blob_send_command("FLASH", buf, len, NULL);
}

#define CHUNK_SIZE 4096
static int ezx_blob_dload_program(u_int32_t addr, char *data, int size, int v)
{
	u_int32_t cur_addr;
	char *cur_data;
	int err;
	for (cur_addr = addr, cur_data = data;
	     cur_addr < (addr + size);
	     cur_addr += CHUNK_SIZE, cur_data += CHUNK_SIZE) {
		int remain = (data + size) - cur_data;
		if (remain > CHUNK_SIZE)
			remain = CHUNK_SIZE;
		if ((err = ezx_blob_cmd_rbin(cur_addr, remain, cur_data)) < 0)
			break;
		if (v)
			info("\b\b\b%02d%%",
			     (int)((100 * (cur_data - data)) / size));
	}
	if (err < 0)
		return err;
	if (v)
		info("\b\b\b\b100%% OK\n");

	return 0;
}

static int ezx_blob_load_program(u_int16_t phone_id, u_int32_t addr, char *data, int size, int v)
{
	u_int32_t cur_addr;
	char *cur_data;
	int err = 0;

	if (!addr) /* workaround for missing values */
		return -1;

	for (cur_addr = addr, cur_data = data;
	     cur_addr < (addr + size);
	     cur_addr += CHUNK_SIZE, cur_data += CHUNK_SIZE) {
		int remain;
		if (phone_id == 0x6023) /* A1200 needs a fixed chunk size */
			remain = 4096;
		else
			remain = (data + size) - cur_data;
		if (remain > CHUNK_SIZE)
			remain = CHUNK_SIZE;

		if ((err = ezx_blob_cmd_addr(cur_addr)) < 0)
			break;
		if ((err = ezx_blob_cmd_bin(cur_data, remain)) < 0)
			break;
		if (v)
			info("\b\b\b%02d%%",
			     (int)((100 * (cur_data - data)) / size));
	}
	if (err < 0)
		return err;
	if (v)
		info("\b\b\b\b100%% OK\n");
	return 0;
}

#define FLASH_BLOCK_SIZE	0x20000 	/* 128k */
#define MAX_FLASH_SIZE		0x80000		/* 512k */
#define FLASH_TEMP_ADDR		0xa0400000

static int ezx_blob_flash_program(u_int32_t addr, char *data, int size)
{
	u_int32_t cur_addr;
	char *cur_data;
	int pad = (size % FLASH_BLOCK_SIZE) ?
		(FLASH_BLOCK_SIZE - (size % FLASH_BLOCK_SIZE)) : 0;

	info("Will flash %d bytes of data plus %d bytes of padding\n"
	      "(%d bytes total, %d flash blocks, %d usb uploads)\n",
		size, pad, size + pad,
		(size + pad) / FLASH_BLOCK_SIZE +
		((size + pad) % FLASH_BLOCK_SIZE ? 1 : 0),
		(size + pad) / MAX_FLASH_SIZE +
		((size + pad) % MAX_FLASH_SIZE ? 1 : 0));

	info("Flashing:     ");
	for (cur_addr = addr, cur_data = data;
	     cur_addr < (addr + size);
	     cur_addr += MAX_FLASH_SIZE, cur_data += MAX_FLASH_SIZE) {
		int remain = (data + size) - cur_data;

		remain = (remain > MAX_FLASH_SIZE) ? MAX_FLASH_SIZE : remain;

		if (ezx_blob_load_program(0xbeef, FLASH_TEMP_ADDR,
						cur_data, remain, 0) < 0)
			return -1;

		/* pad up to flash block size */
		remain += pad;

		if (ezx_blob_cmd_flash(FLASH_TEMP_ADDR, cur_addr, remain) < 0)
			return -1;

		info("\b\b\b%02d%%",
		     (int)((100 * (cur_data - data)) / size));
	}
	info("\b\b\b\b100%% OK\n");
	return 0;
}

static int is_valid_addr(char *addr)
{
	unsigned int x, is_dec = 1, is_hex = 1;
	for (x = 0; x < strlen(addr); x++) {
		if ((x == 0 && addr[x] != '0') ||
		    (x == 1 && addr[x] != 'x') ||
		    (x > 1 && !isxdigit(addr[x])))
			is_hex = 0;
		if (!isdigit(addr[x]))
			is_dec = 0;
	}
	if (!is_dec && !is_hex)
		return 0;
	return 1;
}

static void usage()
{
	info("upload a kernel:\n"
	     "   boot_usb <kernel> [machid] [cmdline] [initrd]\n\n"
	     "gen-blob specific commands:\n"
	     "   boot_usb read <addr> <size> <file>\t"
	     "read memory contents (ram or flash)\n"
	     "   boot_usb write <addr> <file>\t\t"
	     "write to RAM memory\n"
	     "   boot_usb flash <addr> <file>\t\t"
	     "write to flash memory\n"
	     "   boot_usb jump <addr>\t\t\t"
	     "execute code at ram address\n"
	     "   boot_usb setflag usb|dumpkeys\t"
	     "set memory flag for gen-blob\n"
	     "   boot_usb off\t\t\t\t"
	     "power off the phone\n\n");

	info("upload a kernel:\n"
	     "You can use hexadecimal and decimal "
	     "for <addr> and <size> arguments,\n"
	     "for hexadecimal you need the '0x' prefix, just like in C.\n");

	info("\nmachid table:\n"
	     "\t   0\tdon't setup a mach id\n"
	     "\t 867\told EZX mach id (default)\n"
	     "\t1740\tA780\n"
	     "\t1741\tE680\n"
	     "\t1742\tA1200\n"
	     "\t1743\tE6\n"
	     "\t1744\tE2\n"
	     "\t1745\tA910\n\n");
}

int main(int argc, char *argv[])
{
	char *prog;
	struct stat st;
	int fd;
	struct tag *tag;
	struct tag *first_tag;
	int tagsize;
	char *asm_code;
	int k_offset = 0;
	int mach_id = 867; /* 867 is the old EZX mach id */

	if (argc < 2) {
		usage();

		error("Too few arguments.");
		exit(1);
	}

	ezx_device_open();

//#ifdef DEBUG /* query information only if debugging */
	if (ezx_blob_send_command("RQSN", NULL, 0, NULL) < 0) {
		error("RQSN");
		exit(1);
	}
	if (ezx_blob_send_command("RQVN", NULL, 0, NULL) < 0) {
		error("RQVN");
		exit(1);
	}
//#endif
	if (phone.product_id == 0xbeef) {
		if (!strcmp(argv[1], "read")) {
			u_int32_t addr;
			u_int32_t size;
			unsigned int len = 0;

			if (argc != 5) {
				printf("usage: %s read <addr> <size> <file>\n",
					argv[0]);
				exit(1);
			}

			fd = open(argv[4], O_CREAT | O_WRONLY, 0644);
			if (fd < 0 || fstat(fd, &st) < 0) {
				error("%s: %s", argv[4], strerror(errno));
				exit(1);
			}
			if (!is_valid_addr(argv[2]) || !is_valid_addr(argv[3])) {
				error("invalid argument");
				exit(1);
			}
			if ((sscanf(argv[3], "0x%x", &size) != 1))
				size = atoi(argv[3]);
			if ((sscanf(argv[2], "0x%x", &addr) != 1))
				addr = atoi(argv[2]);

			if (size < 8 || size % 8 || addr < 0 || addr % 8) {
				error("invalid parameter %d %d", addr, size);
				exit(1);
			}
			info("Downloading:     ");
			if ((prog = malloc(size)) == NULL) {
				error("failed to alloc memory");
				exit(1);
			}
			if (ezx_blob_dload_program(addr, prog, size, 1)) {
				error("download failed\n");
				exit(1);
			}
			while (len < size) {
				int l = write(fd, prog, size - len);
				if (l < 0) {
					error("write error");
					exit(1);
				}
				len += l;
			}
			close(fd);
			free(prog);
			exit(0);
		} else if (!strcmp(argv[1], "flash")) {
			u_int32_t addr;

			if (argc != 4) {
				printf("usage: %s flash <addr> <file>\n",
					argv[0]);
				exit(1);
			}

			if (!is_valid_addr(argv[2])) {
				error("invalid argument (%s)", argv[2]);
				exit(1);
			}
			if (sscanf(argv[2], "0x%x", &addr) != 1)
				addr = atoi(argv[2]);

			if (addr == 0) {
				int c = 30;
				while (c > 0) {
					printf(">>> WILL FLASH THE BOOTLOADER IN %d SECONDS <<<\n", c--);
					sleep(1);
				}
			}

			if ((fd = open(argv[3], O_RDONLY)) < 0) {
				error("%s", strerror(errno));
				exit(1);
			}
			if (fstat(fd, &st) < 0) {
				error("%s", strerror(errno));
				exit(1);
			}
			if ((addr + st.st_size) > 0x4000000 || addr % 0x20000) {
				error("invalid flash file/address");
				exit(1);
			}
			if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
				error("mmap error: %s", strerror(errno));
				exit(1);
			}
			if (ezx_blob_flash_program(addr, prog, st.st_size) < 0) {
				error("flash failed");
				exit(1);
			}
			munmap(prog, st.st_size);
			close(fd);
			exit(0);
		} else if (!strcmp(argv[1], "write")) {
			u_int32_t addr;

			if (argc != 4) {
				printf("usage: %s write <addr> <file>\n",
					argv[0]);
				exit(1);
			}

			if (!is_valid_addr(argv[2])) {
				error("invalid argument (%s)", argv[2]);
				exit(1);
			}
			if (sscanf(argv[2], "0x%x", &addr) != 1)
				addr = atoi(argv[2]);

			if ((fd = open(argv[3], O_RDONLY)) < 0) {
				error("%s", strerror(errno));
				exit(1);
			}
			if (fstat(fd, &st) < 0) {
				error("%s", strerror(errno));
				exit(1);
			}
			if (addr < 0xA0000000 || addr % 0x8 ||
					(addr + st.st_size) > 0xA400000) {
				error("invalid RAM address");
				exit(1);
			}
			if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
				error("mmap error: %s", strerror(errno));
				exit(1);
			}
			if (ezx_blob_load_program(0xbeef, addr, prog,
							st.st_size, 1) < 0) {
				error("upload failed");
				exit(1);
			}
			munmap(prog, st.st_size);
			close(fd);
			exit(0);
		} else if (!strcmp(argv[1], "off")) {
			ezx_blob_send_command("POWER_DOWN", NULL, 0, NULL);
			exit(0);
		} else if (!strcmp(argv[1], "jump")) {
			u_int32_t addr;

			if (argc != 3) {
				printf("usage: %s jump <addr>\n",
					argv[0]);
				exit(1);
			}

			if (!is_valid_addr(argv[2])) {
				error("invalid argument (%s)", argv[2]);
				exit(1);
			}
			if (sscanf(argv[2], "0x%x", &addr) != 1)
				addr = atoi(argv[2]);
			if (addr < 0xa0000000 || addr > 0xa2000000 || addr % 8) {
				error("invalid addr");
				exit(1);
			}
			if (ezx_blob_cmd_jump(addr) < 0) {
				error("jump failed");
				exit(1);
			}
			exit(0);
		}
	}
	if (!strcmp(argv[1], "setflag")) {
		unsigned int flag = 0;
		if (!strcmp(argv[2], "usb"))
			flag = 0x0D3ADCA7;
		else if (!strcmp(argv[2], "dumpkeys"))
			flag = 0x1EE7F1A6;
		if (flag) {
			if (ezx_blob_load_program(phone.product_id, 0xa1000000, (char *)&flag, 4, 1) < 0) {
				error("flag send failed");
				exit(1);
			}
			exit(0);
		} else {
			printf("usage: %s setflag usb|dumpkeys\n", argv[0]);
			exit(1);
		}
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		error("%s: %s", argv[1], strerror(errno));
		exit(1);
	}
	if (fstat(fd, &st) < 0) {
		error("%s: %s", argv[1], strerror(errno));
		exit(1);
	}
	/* mmap kernel image passed as parameter */
	if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
		error("mmap error: %s", strerror(errno));
		exit(1);
	}

	if (argc >= 3)
		mach_id = atoi(argv[2]);

	if (phone.code_size > 0 && mach_id > 0) {
		info("Sending mach id code %d:     ", mach_id);
		if ((asm_code = malloc(CHUNK_SIZE)) == NULL) {
			error("failed to alloc memory");
			exit(1);
		}
		memset(asm_code, 0, sizeof(asm_code));
		memcpy(asm_code, phone.code, phone.code_size);
		*(u_int32_t *)(asm_code + phone.code_size) = mach_id;

		if (ezx_blob_load_program(phone.product_id, phone.kernel_addr, asm_code, CHUNK_SIZE, 1) < 0) {
			error("asm code send failed");
			exit(1);
		}
		k_offset += 4096;
	}

	info("Uploading kernel:     ");
	if (ezx_blob_load_program(phone.product_id, phone.kernel_addr + k_offset, prog, st.st_size, 1) < 0) {
		error("kernel upload failed");
		exit(1);
	}

	munmap(prog, st.st_size);
	close(fd);
	prog = NULL;

	if (!phone.params_addr) {
		info("Warning, params is not supported on your phone, please consider using gen-blob\n");
		goto run_kernel;
	}

	/* send boot_params */

	/* we will always send at least 4 tags (core + (2 * mem) + none) */
	tagsize = (sizeof(struct tag_header) * 4) + sizeof(struct tag_core) +
			(sizeof(struct tag_mem32) * 2);

	switch (argc) {
	case 5:			/* with initrd - 6 tags */
		tagsize += sizeof(struct tag_header) +
			sizeof(struct tag_initrd);
	case 4:			/* with cmdline - 5+ tags */
		tagsize += sizeof(struct tag_header) +
			((strlen(argv[3]) + 5) > COMMAND_LINE_SIZE ?
			COMMAND_LINE_SIZE : strlen(argv[3]) + 5);
	default:
		break;

	}

	if (!(tag = malloc(tagsize))) {
		error("cannot alloc %d bytes for params", tagsize);
		exit(1);
	}
	first_tag = tag;

	tag->hdr.tag = ATAG_CORE;
	tag->hdr.size = tag_size(tag_core);
	tag->u.core.flags = 0;
	tag->u.core.pagesize = 0;
	tag->u.core.rootdev = 0;

	tag = tag_next(tag);
	tag->hdr.tag = ATAG_MEM;
	tag->hdr.size = tag_size(tag_mem32);
	tag->u.mem.start = 0xa0000000;
	tag->u.mem.size = 32 * 1024 * 1024;

	tag = tag_next(tag);
	tag->hdr.tag = ATAG_MEM;
	tag->hdr.size = tag_size(tag_mem32);
	tag->u.mem.start = 0xac000000;
	tag->u.mem.size = 16 * 1024 * 1024;

	if (argc < 4)
		goto send_params;

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
		exit(1);
	}
	if (!(prog = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0))) {
		error("mmap error: %s", strerror(errno));
		exit(1);
	}
	info("Uploading initrd:     ");
	if (ezx_blob_load_program(phone.product_id, phone.initrd_addr, prog, st.st_size, 1) < 0) {
		error("initrd upload failed");
		exit(1);
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
	if (ezx_blob_load_program(phone.product_id, phone.params_addr, (void *) first_tag, tagsize, 1) < 0) {
		error("params upload failed");
		exit(1);
	}
run_kernel:
	info("Calling the kernel...\n");
	if (ezx_blob_cmd_jump(phone.kernel_addr) < 0) {
		error("kernel jump failed");
		exit(1);
	}
	info("DONE\n");
	exit(0);
}
