/* cdt_parse - parses cdt.bin, the flash layout table used on some Moto phones
 *
 * Copyright (C) 2010  Antonio Ospite <ospite@studenti.unina.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Thanks to sabrod and to the Motorola Milestone hackers:
 * http://and-developers.com/partitions:cdt
 *
 * Tutorial:
 * sudo ./moto-boot-usb read 0x00060800 129024 cdt.bin
 * ./cdt_parse cdt.bin
 */

/* TODO: make the print fuinction endiannes-safe */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct part_info {
	uint64_t nparts; /* used only for the first entry to tell
			    how many entries there are in the file. */
	uint8_t CGname[32];
	uint16_t CGn;
	uint16_t sig_type;
	uint32_t start_addr;
	uint32_t end_addr;
	uint32_t base_addr; /* base_address?
			       see http://and-developers.com/partitions:cdt */
	uint32_t sig_start;
	uint32_t sig_end;

};

static int parse_entry(unsigned char *buffer, struct part_info *partition)
{
	unsigned char *iter;

	/* if the name is null, the we assume the entry is not valid */
	if (buffer[sizeof (partition->nparts)] == 0)
		return 1;

	iter = buffer;

	memcpy(&partition->nparts, iter, sizeof (partition->nparts));
	iter += sizeof (partition->nparts);

	memcpy(&partition->CGname, iter, sizeof (partition->CGname));
	iter += sizeof (partition->CGname);

	memcpy(&partition->CGn, iter, sizeof (partition->CGn));
	iter += sizeof (partition->CGn);

	memcpy(&partition->sig_type, iter, sizeof (partition->sig_type));
	iter += sizeof (partition->sig_type);

	memcpy(&partition->start_addr, iter, sizeof (partition->start_addr));
	iter += sizeof (partition->start_addr);

	memcpy(&partition->end_addr, iter, sizeof (partition->end_addr));
	iter += sizeof (partition->end_addr);

	memcpy(&partition->base_addr, iter, sizeof (partition->base_addr));
	iter += sizeof (partition->base_addr);

	memcpy(&partition->sig_start, iter, sizeof (partition->sig_start));
	iter += sizeof (partition->sig_start);

	memcpy(&partition->sig_end, iter, sizeof (partition->sig_end));
	iter += sizeof (partition->sig_end);

	return 0;
}

static void print_repeat(char c, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		printf("%c", c);
}

static void print_entry(struct part_info *partition)
{
	printf("| %-32s | %6d | %8d | 0x%08x | 0x%08x | 0x%08x | 0x%08x | 0x%08x | %d\n",
			partition->CGname,
			partition->CGn,
			partition->sig_type,
			partition->start_addr,
			partition->end_addr,
			partition->base_addr,
			partition->sig_start,
			partition->sig_end,
			
			(partition->end_addr - partition->start_addr + 1));

}

static void print_flashmap(struct part_info *flashmap, unsigned int nparts)
{
	unsigned int i;

	printf(".");
	print_repeat('-', 117);
	printf(".\n");

	printf("| EZX PHONE CDT TABLE");
	print_repeat(' ', 98);
	printf("\\\n");

	printf("|");
	print_repeat('-', 119);
	printf("|\n");
	printf("| %32s | %6s | %8s | %10s | %10s | %10s | %10s | %10s | %s\n",
			"NAME", "CG_NUM", "SIG_TYPE", "START_ADDR", "END_ADDR",
			"BASE_ADDR", "SIG_START", "SIG_END", "SIZE");

	for (i = 0; i < nparts; i++)
		print_entry(&flashmap[i]);

	printf("|");
	print_repeat('_', 119);
	printf("|\n");
}

static void usage(const char *name)
{
	printf("usage: %s <cdt.bin>\n", name);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	unsigned char buffer[72];
	struct part_info *flashmap;
	uint64_t nparts;
	unsigned int i;
	int ret = 1;
	int err = 0;

	if (argc != 2) {
		usage(argv[0]);
		exit(1);
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		perror(argv[1]);
		exit(1);
	}

	ret = fread(&nparts, 8, 1, fp);
	if (ret < 1) {
		if (feof(fp)) {
			perror("fread nparts, feof");
		} else if (ferror(fp)) {
			perror("fread nparts, ferror");
		} else {
			perror("fread nparts");
		}
		exit(1);
	}
	rewind(fp);

	flashmap = calloc(nparts, sizeof(*flashmap));
	if (flashmap == NULL) {
		perror("calloc flashmap");
		exit(1);
	}

	for (i = 0; i < nparts; i++) {

		ret = fread(buffer, 64, 1, fp);
		if (ret < 1) {
			if (feof(fp)) {
				perror("fread, feof");
			} else if (ferror(fp)) {
				perror("fread, ferror");
			} else {
				perror("fread");
			}
			exit(1);
		}

		err = parse_entry(buffer, &flashmap[i]);
		if (err) {
			fprintf(stderr, "Cannot parse entry.\n");
			exit(1);
		}
	}
	fclose(fp);

	print_flashmap(flashmap, nparts);

	exit(0);
}
