/*
 * SPI flash interface
 *
 * Copyright (C) 2008 Atmel Corporation
 * Copyright (C) 2010 Reinhard Meyer, EMK Elektronik
 *
 * Licensed under the GPL-2 or later.
 */

#include <common.h>
#include <fdtdec.h>
#include <malloc.h>
#include <spi.h>
#include <spi_flash.h>
#include <watchdog.h>
#include <edma.h>
#include <hw_edma_tpcc.h>
#include <hw_edma_tc.h>

#include "spi_flash_internal.h"

DECLARE_GLOBAL_DATA_PTR;

static void spi_flash_addr(u32 addr, u8 *cmd)
{
	/* cmd[0] is actual command */
	cmd[1] = addr >> 16;
	cmd[2] = addr >> 8;
	cmd[3] = addr >> 0;
}

static int spi_flash_read_write(struct spi_slave *spi,
				const u8 *cmd, size_t cmd_len,
				const u8 *data_out, u8 *data_in,
				size_t data_len)
{
	unsigned long flags = SPI_XFER_BEGIN;
	int ret;

	if (data_len == 0)
		flags |= SPI_XFER_END;

	ret = spi_xfer(spi, cmd_len * 8, cmd, NULL, flags);
	if (ret) {
		debug("SF: Failed to send command (%zu bytes): %d\n",
				cmd_len, ret);
	} else if (data_len != 0) {
		if (spi->quad_enable)
			flags = SPI_6WIRE;
		else
			flags = 0;

		ret = spi_xfer(spi, data_len * 8, data_out, data_in, flags |
			       SPI_XFER_END);
		if (ret)
			debug("SF: Failed to transfer %zu bytes of data: %d\n",
					data_len, ret);
	}

	return ret;
}

int spi_flash_cmd(struct spi_slave *spi, u8 cmd, void *response, size_t len)
{
	return spi_flash_cmd_read(spi, &cmd, 1, response, len);
}

int spi_flash_cmd_read(struct spi_slave *spi, const u8 *cmd,
		size_t cmd_len, void *data, size_t data_len)
{
	return spi_flash_read_write(spi, cmd, cmd_len, NULL, data, data_len);
}

int spi_flash_cmd_write(struct spi_slave *spi, const u8 *cmd, size_t cmd_len,
		const void *data, size_t data_len)
{
	return spi_flash_read_write(spi, cmd, cmd_len, data, NULL, data_len);
}

int spi_flash_cmd_wait_ready(struct spi_flash *flash, unsigned long timeout)
{
	struct spi_slave *spi = flash->spi;
	unsigned long timebase;
	int ret;
	u8 status;
	u8 check_status = 0x0;
	u8 poll_bit = STATUS_WIP;
	u8 cmd = flash->poll_cmd;

	if (cmd == CMD_FLAG_STATUS) {
		poll_bit = STATUS_PEC;
		check_status = poll_bit;
	}

	ret = spi_xfer(spi, 8, &cmd, NULL, SPI_XFER_BEGIN);
	if (ret) {
		debug("SF: fail to read %s status register\n",
		      cmd == CMD_READ_STATUS ? "read" : "flag");
		return ret;
	}

	timebase = get_timer(0);
	do {
		WATCHDOG_RESET();

		ret = spi_xfer(spi, 8, NULL, &status, 0);
		if (ret)
			return -1;

		if ((status & poll_bit) == check_status)
			break;

	} while (get_timer(timebase) < timeout);

	spi_xfer(spi, 0, NULL, NULL, SPI_XFER_END);

	if ((status & poll_bit) == check_status)
		return 0;

	/* Timed out */
	debug("SF: time out!\n");
	return -1;
}

int spi_flash_write_common(struct spi_flash *flash, const u8 *cmd,
		size_t cmd_len, const void *buf, size_t buf_len)
{
	struct spi_slave *spi = flash->spi;
	unsigned long timeout = SPI_FLASH_PROG_TIMEOUT;
	int ret;

	if (buf == NULL)
		timeout = SPI_FLASH_PAGE_ERASE_TIMEOUT;

	ret = spi_claim_bus(flash->spi);
	if (ret) {
		debug("SF: unable to claim SPI bus\n");
		return ret;
	}

	ret = spi_flash_cmd_write_enable(flash);
	if (ret < 0) {
		debug("SF: enabling write failed\n");
		return ret;
	}

	ret = spi_flash_cmd_write(spi, cmd, cmd_len, buf, buf_len);
	if (ret < 0) {
		debug("SF: write cmd failed\n");
		return ret;
	}

	ret = spi_flash_cmd_wait_ready(flash, timeout);
	if (ret < 0) {
		debug("SF: write %s timed out\n",
		      timeout == SPI_FLASH_PROG_TIMEOUT ?
			"program" : "page erase");
		return ret;
	}

	spi_release_bus(spi);

	return ret;
}

int spi_flash_cmd_erase(struct spi_flash *flash, u32 offset, size_t len)
{
	u32 erase_size;
	u8 cmd[4];
	int ret = -1;

	erase_size = flash->sector_size;
	if (offset % erase_size || len % erase_size) {
		debug("SF: Erase offset/length not multiple of erase size\n");
		return -1;
	}

	if (erase_size == 4096)
		cmd[0] = CMD_ERASE_4K;
	else
		cmd[0] = CMD_ERASE_64K;

	while (len) {
#ifdef CONFIG_SPI_FLASH_BAR
		u8 bank_sel;

		bank_sel = offset / SPI_FLASH_16MB_BOUN;

		ret = spi_flash_cmd_bankaddr_write(flash, bank_sel);
		if (ret) {
			debug("SF: fail to set bank%d\n", bank_sel);
			return ret;
		}
#endif
		spi_flash_addr(offset, cmd);

		debug("SF: erase %2x %2x %2x %2x (%x)\n", cmd[0], cmd[1],
		      cmd[2], cmd[3], offset);

		ret = spi_flash_write_common(flash, cmd, sizeof(cmd), NULL, 0);
		if (ret < 0) {
			debug("SF: erase failed\n");
			break;
		}

		offset += erase_size;
		len -= erase_size;
	}

	return ret;
}

int spi_flash_cmd_write_multi(struct spi_flash *flash, u32 offset,
		size_t len, const void *buf)
{
	unsigned long byte_addr, page_size;
	size_t chunk_len, actual;
	u8 cmd[4];
	int ret = -1;

	page_size = flash->page_size;

	cmd[0] = CMD_PAGE_PROGRAM;
	for (actual = 0; actual < len; actual += chunk_len) {
#ifdef CONFIG_SPI_FLASH_BAR
		u8 bank_sel;

		bank_sel = offset / SPI_FLASH_16MB_BOUN;

		ret = spi_flash_cmd_bankaddr_write(flash, bank_sel);
		if (ret) {
			debug("SF: fail to set bank%d\n", bank_sel);
			return ret;
		}
#endif
		byte_addr = offset % page_size;
		chunk_len = min(len - actual, page_size - byte_addr);

		if (flash->spi->max_write_size)
			chunk_len = min(chunk_len, flash->spi->max_write_size);

		spi_flash_addr(offset, cmd);

		debug("PP: 0x%p => cmd = { 0x%02x 0x%02x%02x%02x } chunk_len = %zu\n",
		      buf + actual, cmd[0], cmd[1], cmd[2], cmd[3], chunk_len);

		ret = spi_flash_write_common(flash, cmd, sizeof(cmd),
					buf + actual, chunk_len);
		if (ret < 0) {
			debug("SF: write failed\n");
			break;
		}

		offset += chunk_len;
	}

	return ret;
}

int spi_flash_read_common(struct spi_flash *flash, const u8 *cmd,
		size_t cmd_len, void *data, size_t data_len)
{
	struct spi_slave *spi = flash->spi;
	int ret;

	ret = spi_claim_bus(flash->spi);
	if (ret) {
		debug("SF: unable to claim SPI bus\n");
		return ret;
	}

	ret = spi_flash_cmd_read(spi, cmd, cmd_len, data, data_len);
	if (ret < 0) {
		debug("SF: read cmd failed\n");
		return ret;
	}

	spi_release_bus(spi);

	return ret;
}

#if defined(CONFIG_SPL_EDMA_SUPPORT)
/*Adding edma support */
void qspi_readsectors_edma(void *dst_addr, void *src_offset_addr, unsigned int length,
                           unsigned int edma_ch_num)
{
    EDMA3CCPaRAMEntry edma_param;
    int           b_cnt_value = 1;
    int           rem_bytes  = 0;
    int           a_cnt_value = length;
    unsigned int          addr      = (unsigned int) (dst_addr);
    unsigned int          max_acnt  = 0x7FFFU;
    if (length > max_acnt)
    {
        b_cnt_value = (length / max_acnt);
        rem_bytes  = (length % max_acnt);
        a_cnt_value = max_acnt;
    }

    /* Compute QSPI address and size */
    edma_param.opt      = 0;
    edma_param.src_addr  = ((unsigned int) src_offset_addr);
    edma_param.dest_addr = addr;
    edma_param.a_cnt     = a_cnt_value;
    edma_param.b_cnt     = b_cnt_value;
    edma_param.c_cnt     = 1;
    edma_param.src_bidx  = a_cnt_value;
    edma_param.dest_bidx = a_cnt_value;
    edma_param.src_cidx  = 0;
    edma_param.dest_cidx = 0;
    edma_param.link_addr = 0xFFFF;
    edma_param.opt     |=
        (EDMA_TPCC_OPT_TCINTEN_MASK |
         ((edma_ch_num <<
           EDMA_TPCC_OPT_TCC_SHIFT) &
          EDMA_TPCC_OPT_TCC_MASK) | EDMA_TPCC_OPT_SYNCDIM_MASK);

    edma3_set_param(edma_ch_num, &edma_param);
    edma3_enable_transfer(edma_ch_num, EDMA3_TRIG_MODE_MANUAL);

    while (!(edma3_get_intr_status() & (1 << edma_ch_num))) ;
    edma3_clr_intr(edma_ch_num);
    if (rem_bytes != 0)
    {
        /* Compute QSPI address and size */
        edma_param.opt     = 0;
        edma_param.src_addr =
             (b_cnt_value * max_acnt) + ((unsigned int) src_offset_addr);
        edma_param.dest_addr = (addr + (max_acnt * b_cnt_value));
        edma_param.a_cnt     = rem_bytes;
        edma_param.b_cnt     = 1;
        edma_param.c_cnt     = 1;
        edma_param.src_bidx  = rem_bytes;
        edma_param.dest_bidx = rem_bytes;
        edma_param.src_cidx  = 0;
        edma_param.dest_cidx = 0;
        edma_param.link_addr = 0xFFFF;
        edma_param.opt     |=
            (EDMA_TPCC_OPT_TCINTEN_MASK |
             ((edma_ch_num << EDMA_TPCC_OPT_TCC_SHIFT) & EDMA_TPCC_OPT_TCC_MASK));
        edma3_set_param(edma_ch_num, &edma_param);
        edma3_enable_transfer(edma_ch_num,
                            EDMA3_TRIG_MODE_MANUAL);

        while (!(edma3_get_intr_status() & (1 << edma_ch_num))) ;
        edma3_clr_intr(edma_ch_num);
    }
    *((unsigned int *) src_offset_addr) += length;
}
#endif

int spi_flash_cmd_read_quad(struct spi_flash *flash, u32 offset,
		size_t len, void *data)
{
	struct spi_slave *spi = flash->spi;

	unsigned long byte_addr;
	size_t chunk_len, actual;
	int ret = 0;
	u8 cmd[5];

	spi->quad_enable = 1;
	/* Handle memory-mapped SPI */
	if (flash->memory_map) {
		spi_xfer(flash->spi, 0, NULL, NULL, SPI_XFER_MEM_MAP);

       #if defined(CONFIG_SPL_EDMA_SUPPORT)
         qspi_readsectors_edma(data,flash->memory_map+offset,len,1);
       #else
         memcpy(data, flash->memory_map + offset, len);
       #endif

		spi_xfer(flash->spi, 0, NULL, NULL, SPI_XFER_MEM_MAP_END);
		return 0;
	}

	cmd[0] = CMD_READ_ARRAY_QUAD;
	cmd[4] = 0x00;
	byte_addr = offset % SF_MAX_CHUNK_LEN;
	for (actual = 0; actual < len; actual += chunk_len) {
		/* HACK: Read in chunks of SF_MAX_CHUNK_LEN */
		chunk_len = min(len - actual, SF_MAX_CHUNK_LEN - byte_addr);

		spi_flash_addr (offset + actual, cmd);


		ret = spi_flash_read_common(flash, cmd, sizeof(cmd),
				data + actual, chunk_len);
		if (ret < 0) {
			debug("SF: read failed");
			break;
		}

		byte_addr += chunk_len;
		byte_addr %= SF_MAX_CHUNK_LEN;
	}

	return ret;
}

int spi_flash_cmd_read_fast(struct spi_flash *flash, u32 offset,
		size_t len, void *data)
{
	u8 cmd[5], bank_sel = 0;
	int ret = -1;
	unsigned long byte_addr;
	size_t chunk_len, actual;

	/* Handle memory-mapped SPI */
	if (flash->memory_map) {
		spi_xfer(flash->spi, 0, NULL, NULL, SPI_XFER_MEM_MAP);
		memcpy(data, flash->memory_map + offset, len);
		spi_xfer(flash->spi, 0, NULL, NULL, SPI_XFER_MEM_MAP_END);
		return 0;
	}

	cmd[0] = CMD_READ_ARRAY_FAST;
	cmd[4] = 0x00;
	byte_addr = offset % SF_MAX_CHUNK_LEN;
	for (actual = 0; actual < len; actual += chunk_len) {
		/* HACK: Read in chunks of SF_MAX_CHUNK_LEN */
		chunk_len = min(len - actual, SF_MAX_CHUNK_LEN - byte_addr);

		spi_flash_addr (offset + actual, cmd);
#ifdef CONFIG_SPI_FLASH_BAR
		bank_sel = (offset + actual) / SPI_FLASH_16MB_BOUN;

		ret = spi_flash_cmd_bankaddr_write(flash, bank_sel);
		if (ret) {
			debug("SF: fail to set bank%d\n", bank_sel);
			return ret;
		}
#endif

		ret = spi_flash_read_common(flash, cmd, sizeof(cmd),
				data + actual, chunk_len);
		if (ret < 0) {
			debug("SF: read failed\n");
			break;
		}
		byte_addr += chunk_len;
		byte_addr %= SF_MAX_CHUNK_LEN;
	}
	return ret;
}

int spi_flash_cmd_write_status(struct spi_flash *flash, u8 sr)
{
	u8 cmd;
	int ret;

	cmd = CMD_WRITE_STATUS;
	ret = spi_flash_write_common(flash, &cmd, 1, &sr, 1);
	if (ret < 0) {
		debug("SF: fail to write status register\n");
		return ret;
	}

	return 0;
}

#ifdef CONFIG_SPI_FLASH_BAR
int spi_flash_cmd_bankaddr_write(struct spi_flash *flash, u8 bank_sel)
{
	u8 cmd;
	int ret;

	if (flash->bank_curr == bank_sel) {
		debug("SF: not require to enable bank%d\n", bank_sel);
		return 0;
	}

	cmd = flash->bank_write_cmd;
	ret = spi_flash_write_common(flash, &cmd, 1, &bank_sel, 1);
	if (ret < 0) {
		debug("SF: fail to write bank register\n");
		return ret;
	}
	flash->bank_curr = bank_sel;

	return 0;
}

int spi_flash_bank_config(struct spi_flash *flash, u8 idcode0)
{
	u8 cmd;
	u8 curr_bank = 0;

	/* discover bank cmds */
	switch (idcode0) {
	case SPI_FLASH_SPANSION_IDCODE0:
		flash->bank_read_cmd = CMD_BANKADDR_BRRD;
		flash->bank_write_cmd = CMD_BANKADDR_BRWR;
		break;
	case SPI_FLASH_STMICRO_IDCODE0:
	case SPI_FLASH_WINBOND_IDCODE0:
		flash->bank_read_cmd = CMD_EXTNADDR_RDEAR;
		flash->bank_write_cmd = CMD_EXTNADDR_WREAR;
		break;
	default:
		printf("SF: Unsupported bank commands %02x\n", idcode0);
		return -1;
	}

	/* read the bank reg - on which bank the flash is in currently */
	cmd = flash->bank_read_cmd;
	if (flash->size > SPI_FLASH_16MB_BOUN) {
		if (spi_flash_read_common(flash, &cmd, 1, &curr_bank, 1)) {
			debug("SF: fail to read bank addr register\n");
			return -1;
		}
		flash->bank_curr = curr_bank;
	} else {
		flash->bank_curr = curr_bank;
	}

	return 0;
}
#endif

int spi_flash_en_quad_mode(struct spi_flash *flash)
{
	u8 stat, con, cd;
	u16 cr;
	int ret;
	cd = CMD_WRITE_STATUS;

	ret = spi_flash_cmd_write_enable(flash);
	if (ret < 0) {
		debug("SF: enabling write failed\n");
		goto out;
	}
	ret = spi_flash_cmd(flash->spi, CMD_READ_STATUS, &stat, 1);
	ret = spi_flash_cmd(flash->spi, CMD_READ_CONFIG, &con, 1);
	if (ret < 0) {
		debug("%s: SF: read CR failed\n", __func__);
		goto out;
	}
	/* Byte 1 - status reg, Byte 2 - config reg */
	cr = ((con | (0x1 << 1)) << 8) | (stat << 0);

	ret = spi_flash_cmd_write(flash->spi, &cd, 1, &cr, 2);
	if (ret) {
		debug("SF: fail to write conf register\n");
		goto out;
	}

	ret = spi_flash_cmd_wait_ready(flash, SPI_FLASH_PROG_TIMEOUT);
	if (ret < 0) {
		debug("SF: write conf register timed out\n");
		goto out;
	}

	ret = spi_flash_cmd(flash->spi, CMD_READ_STATUS, &stat, 1);
	ret = spi_flash_cmd(flash->spi, CMD_READ_CONFIG, &con, 1);
	if (ret < 0) {
		debug("%s: SF: read CR failed\n", __func__);
		goto out;
	}
	debug("%s: *** CR = %x\n", __func__, con);

	ret = spi_flash_cmd_write_disable(flash);
	if (ret < 0) {
		debug("SF: disabling write failed\n");
		goto out;
	}
out:
	return ret;
}

#ifdef CONFIG_OF_CONTROL
int spi_flash_decode_fdt(const void *blob, struct spi_flash *flash)
{
	fdt_addr_t addr;
	fdt_size_t size;
	int node;

	/* If there is no node, do nothing */
	node = fdtdec_next_compatible(blob, 0, COMPAT_GENERIC_SPI_FLASH);
	if (node < 0)
		return 0;

	addr = fdtdec_get_addr_size(blob, node, "memory-map", &size);
	if (addr == FDT_ADDR_T_NONE) {
		debug("%s: Cannot decode address\n", __func__);
		return 0;
	}

	if (flash->size != size) {
		debug("%s: Memory map must cover entire device\n", __func__);
		return -1;
	}
	flash->memory_map = (void *)addr;

	return 0;
}
#endif /* CONFIG_OF_CONTROL */

/*
 * The following table holds all device probe functions
 *
 * shift:  number of continuation bytes before the ID
 * idcode: the expected IDCODE or 0xff for non JEDEC devices
 * probe:  the function to call
 *
 * Non JEDEC devices should be ordered in the table such that
 * the probe functions with best detection algorithms come first.
 *
 * Several matching entries are permitted, they will be tried
 * in sequence until a probe function returns non NULL.
 *
 * IDCODE_CONT_LEN may be redefined if a device needs to declare a
 * larger "shift" value.  IDCODE_PART_LEN generally shouldn't be
 * changed.  This is the max number of bytes probe functions may
 * examine when looking up part-specific identification info.
 *
 * Probe functions will be given the idcode buffer starting at their
 * manu id byte (the "idcode" in the table below).  In other words,
 * all of the continuation bytes will be skipped (the "shift" below).
 */
#define IDCODE_CONT_LEN 0
#define IDCODE_PART_LEN 5
static const struct {
	const u8 shift;
	const u8 idcode;
	struct spi_flash *(*probe) (struct spi_slave *spi, u8 *idcode);
} flashes[] = {
	/* Keep it sorted by define name */
#ifdef CONFIG_SPI_FLASH_ATMEL
	{ 0, 0x1f, spi_flash_probe_atmel, },
#endif
#ifdef CONFIG_SPI_FLASH_EON
	{ 0, 0x1c, spi_flash_probe_eon, },
#endif
#ifdef CONFIG_SPI_FLASH_MACRONIX
	{ 0, 0xc2, spi_flash_probe_macronix, },
#endif
#ifdef CONFIG_SPI_FLASH_SPANSION
	{ 0, 0x01, spi_flash_probe_spansion, },
#endif
#ifdef CONFIG_SPI_FLASH_SST
	{ 0, 0xbf, spi_flash_probe_sst, },
#endif
#ifdef CONFIG_SPI_FLASH_STMICRO
	{ 0, 0x20, spi_flash_probe_stmicro, },
#endif
#ifdef CONFIG_SPI_FLASH_WINBOND
	{ 0, 0xef, spi_flash_probe_winbond, },
#endif
#ifdef CONFIG_SPI_FRAM_RAMTRON
	{ 6, 0xc2, spi_fram_probe_ramtron, },
# undef IDCODE_CONT_LEN
# define IDCODE_CONT_LEN 6
#endif
	/* Keep it sorted by best detection */
#ifdef CONFIG_SPI_FLASH_STMICRO
	{ 0, 0xff, spi_flash_probe_stmicro, },
#endif
#ifdef CONFIG_SPI_FRAM_RAMTRON_NON_JEDEC
	{ 0, 0xff, spi_fram_probe_ramtron, },
#endif
};
#define IDCODE_LEN (IDCODE_CONT_LEN + IDCODE_PART_LEN)

struct spi_flash *spi_flash_probe(unsigned int bus, unsigned int cs,
		unsigned int max_hz, unsigned int spi_mode)
{
	struct spi_slave *spi;
	struct spi_flash *flash = NULL;
	int ret, i, shift;
	u8 idcode[IDCODE_LEN], *idp;

	spi = spi_setup_slave(bus, cs, max_hz, spi_mode);
	if (!spi) {
		printf("SF: Failed to set up slave\n");
		return NULL;
	}

	ret = spi_claim_bus(spi);
	if (ret) {
		debug("SF: Failed to claim SPI bus: %d\n", ret);
		goto err_claim_bus;
	}

	/* Read the ID codes */
	ret = spi_flash_cmd(spi, CMD_READ_ID, idcode, sizeof(idcode));
	if (ret)
		goto err_read_id;

#ifdef DEBUG
	printf("SF: Got idcodes\n");
	print_buffer(0, idcode, 1, sizeof(idcode), 0);
#endif

	/* count the number of continuation bytes */
	for (shift = 0, idp = idcode;
	     shift < IDCODE_CONT_LEN && *idp == 0x7f;
	     ++shift, ++idp)
		continue;

	/* search the table for matches in shift and id */
	for (i = 0; i < ARRAY_SIZE(flashes); ++i)
		if (flashes[i].shift == shift && flashes[i].idcode == *idp) {
			/* we have a match, call probe */
			flash = flashes[i].probe(spi, idp);
			if (flash)
				break;
		}

	if (!flash) {
		printf("SF: Unsupported manufacturer %02x\n", *idp);
		goto err_manufacturer_probe;
	}

#ifdef CONFIG_SPI_FLASH_BAR
	/* Configure the BAR - disover bank cmds and read current bank  */
	ret = spi_flash_bank_config(flash, *idp);
	if (ret < 0)
		goto err_manufacturer_probe;
#endif

#ifdef CONFIG_SF_QUAD_RD
	spi_flash_en_quad_mode(flash);
#endif

#ifdef CONFIG_OF_CONTROL
	if (spi_flash_decode_fdt(gd->fdt_blob, flash)) {
		debug("SF: FDT decode error\n");
		goto err_manufacturer_probe;
	}
#endif
	printf("SF: Detected %s with page size ", flash->name);
	print_size(flash->sector_size, ", total ");
	print_size(flash->size, "");
	if (flash->memory_map)
		printf(", mapped at %p", flash->memory_map);
	puts("\n");
#ifndef CONFIG_SPI_FLASH_BAR
	if (flash->size > SPI_FLASH_16MB_BOUN) {
		puts("SF: Warning - Only lower 16MiB accessible,");
		puts(" Full access #define CONFIG_SPI_FLASH_BAR\n");
	}
#endif

	spi_release_bus(spi);

	return flash;

err_manufacturer_probe:
err_read_id:
	spi_release_bus(spi);
err_claim_bus:
	spi_free_slave(spi);
	return NULL;
}

void *spi_flash_do_alloc(int offset, int size, struct spi_slave *spi,
			 const char *name)
{
	struct spi_flash *flash;
	void *ptr;

	ptr = malloc(size);
	if (!ptr) {
		debug("SF: Failed to allocate memory\n");
		return NULL;
	}
	memset(ptr, '\0', size);
	flash = (struct spi_flash *)(ptr + offset);

	/* Set up some basic fields - caller will sort out sizes */
	flash->spi = spi;
	flash->name = name;
	flash->poll_cmd = CMD_READ_STATUS;

#ifdef CONFIG_SF_QUAD_RD
	flash->read = spi_flash_cmd_read_quad;
#else
	flash->read = spi_flash_cmd_read_fast;
#endif
	flash->write = spi_flash_cmd_write_multi;
	flash->erase = spi_flash_cmd_erase;

	return flash;
}

void spi_flash_free(struct spi_flash *flash)
{
	spi_free_slave(flash->spi);
	free(flash);
}
