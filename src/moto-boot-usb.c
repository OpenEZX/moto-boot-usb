/* moto-boot-usb - Ram Loader for Motorola EZX phones
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

/* for usleep() */
#define _BSD_SOURCE

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

//#define USECS_SLEEP 500

//#define DEBUG

#ifndef DEBUG
#define info(...) do {\
		printf(__VA_ARGS__); \
		fflush(stdout); \
	} while(0)
#else
#define info(...) do {} while(0)
#endif

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
#define dbg(...) do {} while(0)
#endif

#ifdef DEBUG
const char *hexdump(const void *data, int len)
{
	static char string[65535];
	unsigned char *d = (unsigned char *)data;
	int i, left;

	string[0] = '\0';

	if (len < 0)
		return string;

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

/* We set set the machine ID from moto-boot-usb with this assembler tricks
 * beacuse the original blob is not able to do this for us.
 *
 * ldr     r1, [pc, #8]
 * sub     r0, pc, #12
 * add     r0, r0, #4096
 * mov     pc, r0
 */
#define pxa_code "\x08\x10\x9F\xE5\x0C\x00\x4F\xE2\x01\x0A\x80\xE2\x00\xF0\xA0\xE1"
#define pxa_code_s 16

#define EZX_VENDOR_ID 0x22b8
static struct phonetype phonetypes[] = {
{ "A780/E680",        0x6003, 0x02, 0x81, 0xa0300000, 0xa0600000, 0xa0000100, pxa_code, pxa_code_s },
{ "Generic Blob",     0xbeef, 0x02, 0x81, 0xa0200000, 0xa0500000, 0xa0000100, pxa_code, pxa_code_s }, /* pxa_code is temporary here */
{ "A780/E680 Blob2",  0x6021, 0x02, 0x81, 0xa0300000, 0xa0600000, 0xa0000100, pxa_code, pxa_code_s },
{ "E2/A1200/E6/A910", 0x6023, 0x01, 0x82, 0xa0de0000, /*FIXME*/0, /*FIXME*/0, pxa_code, pxa_code_s },
{ "RAZR2 V8",         0x6403, 0x01, 0x82, 0xa0de0000, /*FIXME*/0, /*FIXME*/0, NULL, 0 },
{ "Unknown",          0x0000, 0x00, 0x00, 0x00000000, 0x00000000, 0x00000000, NULL, 0 }
};

#define NUL	0x00
#define STX	0x02
#define	ETX	0x03
#define	RS	0x1E

#define BLOADER_BIT7            0x80
#define BLOADER_ALWAYS_SET_BIT     BLOADER_BIT7
/* Error Codes of Motorola Boot Intrface Specification (taken from blob) */
#define BLOADER_ERR_BAD_CHECKSUM           (BLOADER_ALWAYS_SET_BIT | 0x00)
#define BLOADER_ERR_ERASE_FAILED           (BLOADER_ALWAYS_SET_BIT | 0x01)
#define BLOADER_ERR_ERASE_SUSPENDED        (BLOADER_ALWAYS_SET_BIT | 0x02)
#define BLOADER_ERR_ADDRESS_INVALID        (BLOADER_ALWAYS_SET_BIT | 0x03)
#define BLOADER_ERR_PACKET_SZ_INVALID      (BLOADER_ALWAYS_SET_BIT | 0x04)
#define BLOADER_ERR_UNKNOWN_COMMAND        (BLOADER_ALWAYS_SET_BIT | 0x05)
#define BLOADER_ERR_PROGRAMMING            (BLOADER_ALWAYS_SET_BIT | 0x06)
#define BLOADER_ERR_FLASH_NOT_READY        (BLOADER_ALWAYS_SET_BIT | 0x07)
#define BLOADER_ERR_FLASH_NOT_ERASED       (BLOADER_ALWAYS_SET_BIT | 0x08)
#define BLOADER_ERR_VPP_LOW                (BLOADER_ALWAYS_SET_BIT | 0x09)
#define BLOADER_ERR_GENERAL_FAIL           (BLOADER_ALWAYS_SET_BIT | 0x0A)
#define BLOADER_ERR_DATA_INVALID           (BLOADER_ALWAYS_SET_BIT | 0x0B)
#define BLOADER_ERR_ADDRESS_NOT_UPDATED    (BLOADER_ALWAYS_SET_BIT | 0x0C)
#define BLOADER_ERR_COMMAND_SEQ_INVALID    (BLOADER_ALWAYS_SET_BIT | 0x0D)
#define BLOADER_ERR_FLASH_RAM_VER_MISMATCH (BLOADER_ALWAYS_SET_BIT | 0x0E)
#define BLOADER_ERR_RECEIVE_TIMEOUT        (BLOADER_ALWAYS_SET_BIT | 0x0F)
#define BLOADER_ERR_UPID_AREA_FULL         (BLOADER_ALWAYS_SET_BIT | 0x10)
#define BLOADER_ERR_INVALID_CG0_BARKER     (BLOADER_ALWAYS_SET_BIT | 0X11)
#define BLOADER_ERR_CG0_COPY_FAILED        (BLOADER_ALWAYS_SET_BIT | 0X12)
#define BLOADER_ERR_INVALID_CG4_ADDRESS    (BLOADER_ALWAYS_SET_BIT | 0X13)
#define BLOADER_ERR_CG1_COPY_FAILED        (BLOADER_ALWAYS_SET_BIT | 0X14)
#define BLOADER_ERR_UPID_LAST_SLOT         (BLOADER_ALWAYS_SET_BIT | 0x20)
#define BLOADER_ERR_RETRY_TRANSMIT         (BLOADER_ALWAYS_SET_BIT | 0x21)
#define BLOADER_ERR_UPGRADE_CMD_FAILED     (BLOADER_ALWAYS_SET_BIT | 0x22)
#define BLOADER_ERR_FLASH_SIZE_INVALID     (BLOADER_ALWAYS_SET_BIT | 0x24)

struct bl_error_message {
	uint8_t code;
	char *string;
};

static struct bl_error_message bl_errs[] = {
{BLOADER_ERR_BAD_CHECKSUM,           "BLOADER_ERR_BAD_CHECKSUM"},
{BLOADER_ERR_ERASE_FAILED,           "BLOADER_ERR_ERASE_FAILED"},
{BLOADER_ERR_ERASE_SUSPENDED,        "BLOADER_ERR_ERASE_SUSPENDED"},
{BLOADER_ERR_ADDRESS_INVALID,        "BLOADER_ERR_ADDRESS_INVALID"},
{BLOADER_ERR_PACKET_SZ_INVALID,      "BLOADER_ERR_PACKET_SZ_INVALID"},
{BLOADER_ERR_UNKNOWN_COMMAND,        "BLOADER_ERR_UNKNOWN_COMMAND"},
{BLOADER_ERR_PROGRAMMING,            "BLOADER_ERR_PROGRAMMING"},
{BLOADER_ERR_FLASH_NOT_READY,        "BLOADER_ERR_FLASH_NOT_READY"},
{BLOADER_ERR_FLASH_NOT_ERASED,       "BLOADER_ERR_FLASH_NOT_ERASED"},
{BLOADER_ERR_VPP_LOW,                "BLOADER_ERR_VPP_LOW"},
{BLOADER_ERR_GENERAL_FAIL,           "BLOADER_ERR_GENERAL_FAIL"},
{BLOADER_ERR_DATA_INVALID,           "BLOADER_ERR_DATA_INVALID"},
{BLOADER_ERR_ADDRESS_NOT_UPDATED,    "BLOADER_ERR_ADDRESS_NOT_UPDATED"},
{BLOADER_ERR_COMMAND_SEQ_INVALID,    "BLOADER_ERR_COMMAND_SEQ_INVALID"},
{BLOADER_ERR_FLASH_RAM_VER_MISMATCH, "BLOADER_ERR_FLASH_RAM_VER_MISMATCH"},
{BLOADER_ERR_RECEIVE_TIMEOUT,        "BLOADER_ERR_RECEIVE_TIMEOUT"},
{BLOADER_ERR_UPID_AREA_FULL,         "BLOADER_ERR_UPID_AREA_FULL"},
{BLOADER_ERR_INVALID_CG0_BARKER,     "BLOADER_ERR_INVALID_CG0_BARKER"},
{BLOADER_ERR_CG0_COPY_FAILED,        "BLOADER_ERR_CG0_COPY_FAILED"},
{BLOADER_ERR_INVALID_CG4_ADDRESS,    "BLOADER_ERR_INVALID_CG4_ADDRESS"},
{BLOADER_ERR_CG1_COPY_FAILED,        "BLOADER_ERR_CG1_COPY_FAILED"},
{BLOADER_ERR_UPID_LAST_SLOT,         "BLOADER_ERR_UPID_LAST_SLOT"},
{BLOADER_ERR_RETRY_TRANSMIT,         "BLOADER_ERR_RETRY_TRANSMIT"},
{BLOADER_ERR_UPGRADE_CMD_FAILED,     "BLOADER_ERR_UPGRADE_CMD_FAILED"},
{BLOADER_ERR_FLASH_SIZE_INVALID,     "BLOADER_ERR_FLASH_SIZE_INVALID"},
};

static char *bl_err_mess(uint8_t code)
{
	unsigned int n = sizeof(bl_errs)/sizeof(bl_errs[0]);
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (bl_errs[i].code == code) {
			return bl_errs[i].string;
		}
	}

	return "code unknown";
}


static struct phonetype phone = { "Unknown", 0, 0, 0, 0, 0, 0, NULL, 0 };


/* usb handling */

#define USB_TIMEOUT 50000
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

static void ezx_device_open(void)
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

	ret = usb_bulk_read(hdl, phone.in_ep, buf, sizeof(buf), USB_TIMEOUT);

	dbg("RX(%d): %s\n", ret, hexdump(buf, ret));

	if (ret < 0)
		return ret;

	/*
	 * In case of error, the bootloader will do something like this:
	 *
	 *    static const u8 errStr[] = "ERR";
	 *    u8 error_code_str[2];
	 *
	 *    error_code_str[0] = error_code;
	 *    error_code_str[1] = NUL;
	 *    parse_send_packet((u8 *) errStr, error_code_str, 1);
	 *
	 * And the packet will be:
	 *    STX, 'E', 'R', 'R', RS, error_code, NULL, ETX, NULL
	 * with error code of type u8.
	 */
	if (buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'R')
		ret = -((uint8_t) buf[5]);

	if (b) {
		if (ret < 0)
			memcpy(b, "ERR\0", 4);
		else
			memcpy(b, buf, ret);
	}

	return ret;
}

static int ezx_blob_send_command(const char *command, char *payload, int len, char *reply)
{
	char buf[9000];
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

	dbg("TX(%d): %s\n", cur, hexdump(buf, cur));

	ret = usb_bulk_write(hdl, phone.out_ep, buf, cur, USB_TIMEOUT);
	if (ret < 0)
		return ret;

	/* this usleep is required in order to make the process work.
	 * apparently some race condition in the bootloader if we feed
	 * data too fast
	 */
#ifdef USECS_SLEEP
	usleep(USECS_SLEEP);
#endif

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
	data = (u_int8_t *) reply + 6;
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
	u_int16_t htons_size;

	size += (size % 8) ? (8 - (size % 8)) : 0;

	if (size > 8192)
		return -1;

	memset(buf, 0, sizeof(buf));

	htons_size = htons(size);
	memcpy(buf, &htons_size, 2);
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
	int err = 0;
	for (cur_addr = addr, cur_data = data;
	     cur_addr < (addr + size);
	     cur_addr += CHUNK_SIZE, cur_data += CHUNK_SIZE) {
		int remain = (data + size) - cur_data;
		if (remain > CHUNK_SIZE)
			remain = CHUNK_SIZE;
		if ((err = ezx_blob_cmd_rbin(cur_addr, remain, cur_data)) < 0)
			break;
		if (v)
			info("\rDownloading: %.1f%%",
				(100 * (float)(cur_data - data)) / size);
	}
	if (err < 0) {
		if (v)
			info("\n");
		return err;
	}
	if (v)
		info("\rDownloading: 100%% OK\n");

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
			info("\rUploading: %.1f%%",
				(100 * (float)(cur_data - data)) / size);
	}
	if (err < 0)
		return err;
	if (v)
		info("\rUploading: 100%% OK\n");
	return 0;
}

#define FLASH_BLOCK_SIZE	0x20000		/* 128k */
#define MAX_FLASH_SIZE		0x80000		/* 512k */
#define FLASH_TEMP_ADDR		0xa0400000

static int ezx_blob_flash_program(u_int32_t addr, char *data, int size)
{
	u_int32_t cur_addr;
	char *cur_data;
	int pad = (size % FLASH_BLOCK_SIZE) ?
		(FLASH_BLOCK_SIZE - (size % FLASH_BLOCK_SIZE)) : 0;
	int err = 0;

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

		if ((err = ezx_blob_load_program(0xbeef, FLASH_TEMP_ADDR,
						cur_data, remain, 0)) < 0)
			break;

		/* pad up to flash block size, ONLY when needed (last block).
		   The logic is OK but this check can be made prettier */
		if ((cur_addr + remain) % FLASH_BLOCK_SIZE)
			remain += pad;

		if ((err = ezx_blob_cmd_flash(FLASH_TEMP_ADDR, cur_addr, remain)) < 0)
			break;

		info("\b\b\b%02d%%",
		     (int)((100 * (cur_data - data)) / size));
	}
	if (err < 0)
		return err;

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

static void usage(void)
{
	info("upload a kernel:\n"
	     "   moto-boot-usb <kernel> [machid] [cmdline] [initrd]\n\n"
	     "gen-blob specific commands:\n"
	     "   moto-boot-usb read <addr> <size> <file>\t"
	     "read memory contents (ram or flash)\n"
	     "   moto-boot-usb write <addr> <file>\t\t"
	     "write to RAM memory\n"
	     "   moto-boot-usb flash <addr> <file>\t\t"
	     "write to flash memory\n"
	     "   moto-boot-usb jump <addr>\t\t\t"
	     "execute code at ram address\n"
	     "   moto-boot-usb setflag usb|dumpkeys|passthrough\t"
	     "set memory flag for gen-blob\n"
	     "   moto-boot-usb off\t\t\t\t"
	     "power off the phone\n"
	     "   moto-boot-usb help|--help\t\t\t"
	     "show this help screen\n"
	     "\n");

	info("You can use hexadecimal and decimal "
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

/* moto-boot-usb commands */

static void boot_usb_cmd_read(u_int32_t addr, u_int32_t size, const char *outfilename)
{
	char *prog;
	int fd;
	int ret = 0;
	struct stat st;
	unsigned int len = 0;

	fd = open(outfilename, O_CREAT | O_WRONLY, 0644);
	if (fd < 0 || fstat(fd, &st) < 0) {
		error("%s: %s", outfilename, strerror(errno));
		exit(1);
	}

	if (size < 8 || size % 8 || addr % 8) {
		error("invalid parameter %d %d", addr, size);
		exit(1);
	}
	if ((prog = malloc(size)) == NULL) {
		error("failed to alloc memory");
		exit(1);
	}

	ret = ezx_blob_dload_program(addr, prog, size, 1);
	if (ret < 0)
		error("download failed: %s", bl_err_mess(-ret));

	/* write out the data even on FAILURE */
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
	exit(ret);
}

static void boot_usb_cmd_flash(u_int32_t addr, const char *infilename)
{
	char *prog;
	int fd;
	struct stat st;
	int ret;

	fd = open(infilename, O_RDONLY);
	if (fd < 0) {
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
	
	ret = ezx_blob_flash_program(addr, prog, st.st_size);
	if (ret < 0) {
		error("flash failed: %s", bl_err_mess(-ret));
		munmap(prog, st.st_size);
		close(fd);
		exit(1);
	}

	munmap(prog, st.st_size);
	close(fd);
	exit(0);
}

static void boot_usb_cmd_write(u_int32_t addr, const char *infilename)
{
	char *prog;
	int fd;
	struct stat st;
	int ret;

	fd = open(infilename, O_RDONLY);
	if (fd < 0) {
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

	ret = ezx_blob_load_program(0xbeef, addr, prog, st.st_size, 1);
	if (ret < 0) {
		error("upload failed %s:", bl_err_mess(-ret));
		munmap(prog, st.st_size);
		close(fd);
		exit(1);
	}

	munmap(prog, st.st_size);
	close(fd);
	exit(0);
}

static void boot_usb_cmd_off(void)
{
	int ret;

	ret = ezx_blob_send_command("POWER_DOWN", NULL, 0, NULL);
	if (ret < 0) {
		error("powerdown failed: %s", bl_err_mess(-ret));
		exit(1);
	}

	exit(0);
}

static void boot_usb_cmd_jump(u_int32_t addr)
{
	int ret;

	if (addr < 0xa0000000 || addr > 0xa2000000 || addr % 8) {
		error("invalid addr");
		exit(1);
	}

	ret = ezx_blob_cmd_jump(addr);
	if (ret < 0) {
		error("jump failed: %s", bl_err_mess(-ret));
		exit(1);
	}
	exit(0);
}

static void boot_usb_cmd_setflag(const char *flagname)
{
	unsigned int flag = 0;
	/* flag address used by gen-blob */
	unsigned int addr = 0xa1000000;
	int ret;

	if (!strcmp(flagname, "usb"))
		flag = 0x0D3ADCA7;
	else if (!strcmp(flagname, "dumpkeys"))
		flag = 0x1EE7F1A6;
	else if (!strcmp(flagname, "passthrough")) {
		flag = 0x12345678;
		/* PASS_THRU_FLAG_ADDR used by original blob */
		addr = 0xa0000000;
	}
	else {
		error("unknown flag name '%s', use either usb, dumpkeys or passthrough",
				flagname);
		exit(1);
	}

	ret = ezx_blob_load_program(phone.product_id, addr, (char *)&flag, 4, 1);
	if (ret < 0) {
		error("flag send failed");
		exit(1);
	}

	exit(0);
}

#define _boot_usb_query_cmd(command) do {\
		memset(reply, 0, sizeof(reply)); \
		ret = ezx_blob_send_command(command, NULL, 0, reply); \
		if (ret < 0) \
			error(command ": %d %s", ret, bl_err_mess(-ret)); \
		else {\
			info(command ": %s\n", reply); \
		} \
	} while (0)

static void boot_usb_query_info(void)
{
	int ret;
	char reply[8192];

	_boot_usb_query_cmd("RQHW");

	/* extend querying information only if debugging */
#ifdef DEBUG
	_boot_usb_query_cmd("RQSN");
	_boot_usb_query_cmd("RQVN");
	_boot_usb_query_cmd("RQCS");
	_boot_usb_query_cmd("RQRC");
#endif
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
	int ret;

	if (argc < 2) {
		usage();

		error("Too few arguments.");
		exit(1);
	}

	if (!strcmp(argv[1], "help") || !strcmp(argv[1], "--help")) {
		usage();
		exit(0);
	}


	ezx_device_open();


	/* Gen-blob does not support all the query commands */
	if (phone.product_id != 0xbeef)
		boot_usb_query_info();

	if (phone.product_id == 0xbeef) {
		if (!strcmp(argv[1], "read")) {
			u_int32_t addr;
			u_int32_t size;

			if (argc != 5) {
				printf("usage: %s read <addr> <size> <file>\n",
					argv[0]);
				exit(1);
			}
			if (!is_valid_addr(argv[2]) || !is_valid_addr(argv[3])) {
				error("invalid argument");
				exit(1);
			}
			if ((sscanf(argv[2], "0x%x", &addr) != 1))
				addr = atoi(argv[2]);
			if ((sscanf(argv[3], "0x%x", &size) != 1))
				size = atoi(argv[3]);

			boot_usb_cmd_read(addr, size, argv[4]);

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
				const char *confirmation = "yes, do it, I am sure";
				char user_input[32] = "\0";
				int c = 30;

				printf("WARNING: flashing at address 0 is a dangerous operation!\n");
				printf("Type \"%s\" to continue: ", confirmation);

				if (fgets(user_input, 32, stdin) == NULL) {
					error("fgets failed");
					exit(1);
				}
				/* remove trailing newline */
				user_input[strlen(user_input) - 1] = '\0';

				if (strncmp(user_input, confirmation, 32) != 0)
				{
					error("invalid confirmation string");
					exit(1);
				}

				while (c > 0) {
					printf(">>> WILL FLASH THE BOOTLOADER IN %d SECONDS <<<\n", c--);
					sleep(1);
				}
			}

			boot_usb_cmd_flash(addr, argv[3]);

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

			boot_usb_cmd_write(addr, argv[3]);

		} else if (!strcmp(argv[1], "off")) {
			boot_usb_cmd_off();

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

			boot_usb_cmd_jump(addr);
		}
	}
	if (!strcmp(argv[1], "setflag")) {
		if (argc != 3) {
			printf("usage: %s setflag usb|dumpkeys|passthrough\n", argv[0]);
			exit(1);
		}

		boot_usb_cmd_setflag(argv[2]);
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
		info("Sending mach id code %d\n", mach_id);
		if ((asm_code = malloc(CHUNK_SIZE)) == NULL) {
			error("failed to alloc memory");
			exit(1);
		}
		memset(asm_code, 0, CHUNK_SIZE);
		memcpy(asm_code, phone.code, phone.code_size);
		*(u_int32_t *)(asm_code + phone.code_size) = mach_id;

		ret = ezx_blob_load_program(phone.product_id, phone.kernel_addr,
				asm_code, CHUNK_SIZE, 1);
		if (ret < 0) {
			error("asm code send failed: %s", bl_err_mess(-ret));
			exit(1);
		}
		k_offset += CHUNK_SIZE;
	}

	info("Sending kernel\n");
	ret = ezx_blob_load_program(phone.product_id,
			phone.kernel_addr + k_offset, prog, st.st_size, 1);
	if (ret < 0) {
		error("kernel upload failed: %s", bl_err_mess(-ret));
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
	info("Sending initrd\n");
	ret = ezx_blob_load_program(phone.product_id, phone.initrd_addr, prog,
			st.st_size, 1);
	if (ret < 0) {
		error("initrd upload failed : %s", bl_err_mess(-ret));
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
	info("Sending params\n");
	ret = ezx_blob_load_program(phone.product_id, phone.params_addr,
			(void *) first_tag, tagsize, 1);
	if (ret < 0) {
		error("params upload failed: %s", bl_err_mess(-ret));
		exit(1);
	}
run_kernel:
	info("Calling the kernel...\n");
	ret = ezx_blob_cmd_jump(phone.kernel_addr);
	if (ret < 0) {
		error("kernel jump failed: %s", bl_err_mess(-ret));
		exit(1);
	}
	info("DONE\n");
	exit(0);
}
