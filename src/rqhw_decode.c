/* rqhw_decode - decode reply to the RQHW command from Motorola bootloaders
 *
 * Copyright (C) 2009  Antonio Ospite <ospite@studenti.unina.it>
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
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct phone_rshq {
	char *rshw;
	char *description;
};

static struct phone_rshq phones[] = {
	{
		.rshw        = "RSHW000D0201FF000100",
		.description = "a780 european with GPS EZX AP bootloader Version 3.0 2004-05-18",
	},
	{
		.rshw        = "RSHW000D0201FF000100",
		.description = "e680i EZX AP bootloader Version 3.0 2004-05-18",
	},
	{
		.rshw        = "RSHW011602FFFF001502",
		.description = "a910 old BOOT_G_00.02.15R_MARTINIQUE",
	},
	{
		.rshw        = "RSHW011602FFFF004502",
		.description = "a910 new BOOT_G_00.02.45R_MARTINIQUE",
	},
	{
		.rshw        = "RSHW011602FFFF000502",
		.description = "ROKR E2 BOOT_G_00.02.05R_SUMATRA",
	},
	{
		.rshw        = "RSHW011602FFFF008801",
		.description = "A1200 BOOT_G_00.01.89P_HAINAN",
	},
	{
		.rshw        = "RSHW01FF002C6CFFFFFF",
		.description = "Motorola Droid",
	},
	{
		.rshw        = "RSHW010C02FFFF0007D0",
		.description = "Motorola E398 (T-Mobile edition)",
	},
	{
		.rshw        = "RSHW010C02FF01000A02",
		.description = "Motorola Rockr E1",
	},
	{
		.rshw        = "RSHW00130200FF000300",
		.description = "V360",
	},
};

/* taken from a780-blob source code:
 * http://svn.openezx.org/trunk/src/blob/a780-blob/
 *
 * See include/blob/bl_flash_header.h::typedef struct _FLASH_HEADER
 */
struct hw_desc {
	uint8_t flash_bl_hardware_descriptor_descriptor_type;
	uint8_t flash_bl_hardware_descriptor_hw_chipset_type;
	uint8_t flash_bl_hardware_descriptor_ma_type;
	uint8_t flash_bl_hardware_descriptor_growth0;
	uint8_t flash_bl_hardware_descriptor_growth1;
	uint8_t flash_bl_hardware_descriptor_product_sub_type;
	uint16_t flash_bl_hardware_descriptor_version_number;
};

static int print_hw_desc(char *msg, struct hw_desc *desc)
{
	if (desc == NULL)
		return -1;

	printf("%s\n", msg);

	printf("descriptor_type: %u\n",
			desc->flash_bl_hardware_descriptor_descriptor_type);
	printf("hw_chipset_type: %u\n",
			desc->flash_bl_hardware_descriptor_hw_chipset_type);
	printf("ma_type: %u\n",
			desc->flash_bl_hardware_descriptor_ma_type);
	printf("growth0: %u\n",
			desc->flash_bl_hardware_descriptor_growth0);
	printf("growth1: %u\n",
			desc->flash_bl_hardware_descriptor_growth1);
	printf("product_sub_type: %u\n",
			desc->flash_bl_hardware_descriptor_product_sub_type);
	printf("version_number: %u\n",
			desc->flash_bl_hardware_descriptor_version_number);

	printf("\n");

	return 0;
}

/*
 * Decode the result of the RQHW used
 * in Motorola Boot interface Specification
 *
 * the string has this format:
 *
 *   RSHW000D0201FF000100
 *
 * "RSHW" + 16 ascii chars (8 hex-encoded bytes)
 *
 */
static int rqhw_decode(char *string, struct hw_desc *desc)
{
	int ret;
	union _hw_desc {
		struct hw_desc desc;
		uint8_t data[8];
	} conv;

	/* 4 chars for "RSHW" + 16 characters */
	if (strlen(string) != 20)
		return -1;

	if (strncmp(string, "RSHW", 4))
		return -1;

	ret = sscanf(string + 4,
			"%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
			&conv.data[0], &conv.data[1], &conv.data[2],
			&conv.data[3], &conv.data[4], &conv.data[5],
			&conv.data[6], &conv.data[7]);

	if (ret != 8)
		return -1;

	memcpy(desc, &conv.desc, sizeof(*desc));

	return 0;
}


int main(void)
{
	int ret;
	int i;
	int n;
	struct hw_desc desc;

	n = sizeof(phones)/sizeof(phones[0]);

	for (i = 0; i < n; i++) {
		ret = rqhw_decode(phones[i].rshw, &desc);
		if (ret == 0)
			print_hw_desc(phones[i].description, &desc);
	}

	return 0;
}
