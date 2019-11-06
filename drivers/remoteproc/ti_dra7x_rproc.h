#ifndef REMOTEPROC_TI_DRA7_RPROC_H
#define REMOTEPROC_TI_DRA7_RPROC_H

// SPDX-License-Identifier: GPL-2.0
/*
 * remoteproc for various SoCs
 *
 * Copyright (C) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *      RamPrasad N <x0038811@ti.com>
 */
#include <common.h>
#include <dm.h>
#include <elf.h>
#include <environment.h>
#include <dm/of_access.h>
#include <fs_loader.h>
#include <remoteproc.h>
#include <errno.h>
#include <clk.h>
#include <reset.h>
#include <regmap.h>
#include <syscon.h>
#include <asm/io.h>
#include <misc.h>
#include <power-domain.h>
#include <timer.h>
#include <fs.h>
#include <spl.h>
#include <timer.h>
#include <reset.h>
#include <linux/bitmap.h>

#define DPLL_TIMEOUT                 5000
#define L4_CFG_TARG                  0x4A000000
#define L4_WKUP_TARG                 0x4AE00000
#define IPU2_TARGET_TARG             0x55000000
#define IPU1_TARGET_TARG             0x58800000
#define CTRL_MODULE_CORE             (L4_CFG_TARG + 0x2000)
#define CM_CORE_AON                  (L4_CFG_TARG + 0x5000)
#define CM_CORE                      (L4_CFG_TARG + 0x8000)
#define PRM                          (L4_WKUP_TARG + 0x6000)
#define MPU_CM_CORE_AON              (CM_CORE_AON + 0x300)
#define IPU_CM_CORE_AON              (CM_CORE_AON + 0x500)
#define RTC_CM_CORE_AON              (CM_CORE_AON + 0x740)
#define VPE_CM_CORE_AON              (CM_CORE_AON + 0x760)
#define COREAON_CM_CORE              (CM_CORE + 0x600)
#define CORE_CM_CORE                 (CM_CORE + 0x700)
#define CAM_CM_CORE                  (CM_CORE + 0x1000)
#define DSS_CM_CORE                  (CM_CORE + 0x1100)
#define L3INIT_CM_CORE               (CM_CORE + 0x1300)
#define L4PER_CM_CORE                (CM_CORE + 0x1700)
#define CKGEN_PRM                    (PRM + 0x100)
#define IPU_PRM                      (PRM + 0x500)
#define CORE_PRM                     (PRM + 0x700)
#define WKUPAON_CM                   (PRM + 0x1800)

#define CM_CLKMODE_DPLL_DSP          (0x4A005234)
#define CM_DSP1_CLKSTCTRL            (0x4A005400)
#define CM_DSP2_CLKSTCTRL            (0x4A005600)
#define DSP1_PRM_BASE                (0x4AE06400)
#define DSP2_PRM_BASE                (0x4AE07B00)
#define DSP1_SYS_MMU_CONFIG          (0x40D00018)
#define DSP2_SYS_MMU_CONFIG          (0x41500018)

/* CTRL_CORE_CONTROL_DSP1_RST_VECTOR in TRM */
#define DSP1_BOOTADDR                (0x4A00255C)
/* CTRL_CORE_CONTROL_DSP2_RST_VECTOR in TRM */
#define DSP2_BOOTADDR                (0x4A002560)
#define DRA7XX_CTRL_CORE_DSP_RST_VECT_MASK	(0x3FFFFF << 0)

#define CM_L3MAIN1_CLKSTCTRL         (CORE_CM_CORE + 0x000)
#define CM_IPU2_CLKSTCTRL            (CORE_CM_CORE + 0x200)
#define CM_DMA_CLKSTCTRL             (CORE_CM_CORE + 0x300)
#define CM_EMIF_CLKSTCTRL            (CORE_CM_CORE + 0x400)
#define CM_L4CFG_CLKSTCTRL           (CORE_CM_CORE + 0x600)

#define CM_DSS_CLKSTCTRL             (DSS_CM_CORE + 0x00)
#define CM_CAM_CLKSTCTRL             (CAM_CM_CORE + 0x00)
#define CM_COREAON_CLKSTCTRL         (COREAON_CM_CORE + 0x00)
#define CM_L3INIT_CLKSTCTRL          (L3INIT_CM_CORE + 0x00)
#define CM_GMAC_CLKSTCTRL            (L3INIT_CM_CORE + 0xC0)
#define CM_L4PER_CLKSTCTRL           (L4PER_CM_CORE + 0x000)
#define CM_L4PER_TIMER10_CLKCTRL     (CM_L4PER_CLKSTCTRL + 0x28)
#define CM_L4PER_TIMER11_CLKCTRL     (CM_L4PER_CLKSTCTRL + 0x30)
#define CM_L4PER_TIMER3_CLKCTRL      (CM_L4PER_CLKSTCTRL + 0x40)
#define CM_L4PER_TIMER4_CLKCTRL      (CM_L4PER_CLKSTCTRL + 0x48)
#define CM_L4PER_TIMER9_CLKCTRL      (CM_L4PER_CLKSTCTRL + 0x50)
#define CM_L4PER2_CLKSTCTRL          (L4PER_CM_CORE + 0x1FC)
#define CM_L4PER3_CLKSTCTRL          (L4PER_CM_CORE + 0x210)
#define CM_MPU_CLKSTCTRL             (MPU_CM_CORE_AON + 0x00)
#define CM_RTC_CLKSTCTRL             (RTC_CM_CORE_AON + 0x00)
#define CM_VPE_CLKSTCTRL             (VPE_CM_CORE_AON + 0x00)
#define CM_WKUPAON_CLKSTCTRL         (WKUPAON_CM + 0x00)

#define RM_IPU1_RSTCTRL              (IPU_PRM + 0x10)
#define RM_IPU1_RSTST                (IPU_PRM + 0x14)
#define CM_IPU1_CLKSTCTRL            (IPU_CM_CORE_AON + 0x0)
#define CM_IPU1_IPU1_CLKCTRL         (IPU_CM_CORE_AON + 0x20)
#define CM_IPU2_IPU2_CLKCTRL         (CORE_CM_CORE + 0x220)
#define CM_IPU_CLKSTCTRL             (IPU_CM_CORE_AON + 0x40)
#define CM_IPU_MCASP1_CLKCTRL        (IPU_CM_CORE_AON + 0x50)
#define CM_IPU_TIMER5_CLKCTRL        (IPU_CM_CORE_AON + 0x58)
#define CM_IPU_TIMER6_CLKCTRL        (IPU_CM_CORE_AON + 0x60)
#define CM_IPU_TIMER7_CLKCTRL        (IPU_CM_CORE_AON + 0x68)
#define CM_IPU_TIMER8_CLKCTRL        (IPU_CM_CORE_AON + 0x70)

#define IPU1_LOAD_ADDR         (0xb4000000)
#define MAX_REMOTECORE_BIN_SIZE (12 * 0x100000)

#define IPU2_LOAD_ADDR         (IPU1_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP1_LOAD_ADDR         (IPU2_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP2_LOAD_ADDR         (DSP1_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)

#define IPU1_UNCOMP_LOAD_ADDR         (DSP2_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define IPU2_UNCOMP_LOAD_ADDR         (IPU1_UNCOMP_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP1_UNCOMP_LOAD_ADDR         (IPU2_UNCOMP_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP2_UNCOMP_LOAD_ADDR         (DSP1_UNCOMP_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)

#define PAGE_SHIFT			12
#define PAGESIZE_1M                          0x0
#define PAGESIZE_64K                         0x1
#define PAGESIZE_4K                          0x2
#define PAGESIZE_16M                         0x3
#define LE                                   0
#define BE                                   1
#define ELEMSIZE_8                           0x0
#define ELEMSIZE_16                          0x1
#define ELEMSIZE_32                          0x2
#define MIXED_TLB                            0x0
#define MIXED_CPU                            0x1

#define PGT_SMALLPAGE_SIZE                   0x00001000
#define PGT_LARGEPAGE_SIZE                   0x00010000
#define PGT_SECTION_SIZE                     0x00100000
#define PGT_SUPERSECTION_SIZE                0x01000000

#define PGT_L1_DESC_PAGE                     0x00001
#define PGT_L1_DESC_SECTION                  0x00002
#define PGT_L1_DESC_SUPERSECTION             0x40002

#define PGT_L1_DESC_PAGE_MASK                0xfffffC00
#define PGT_L1_DESC_SECTION_MASK             0xfff00000
#define PGT_L1_DESC_SUPERSECTION_MASK        0xff000000

#define PGT_L1_DESC_SMALLPAGE_INDEX_SHIFT    12
#define PGT_L1_DESC_LARGEPAGE_INDEX_SHIFT    16
#define PGT_L1_DESC_SECTION_INDEX_SHIFT      20
#define PGT_L1_DESC_SUPERSECTION_INDEX_SHIFT 24

#define PGT_L2_DESC_SMALLPAGE               0x02
#define PGT_L2_DESC_LARGEPAGE               0x01

#define PGT_L2_DESC_SMALLPAGE_MASK          0xfffff000
#define PGT_L2_DESC_LARGEPAGE_MASK          0xffff0000

#define DRA7_RPROC_CMA_BASE_IPU1             0x9e000000
#define DRA7_RPROC_CMA_BASE_IPU2             0x99000000
#define DRA7_RPROC_CMA_BASE_DSP1             0xA1000000
#define DRA7_RPROC_CMA_BASE_DSP2             0xA3000000

#define DRA7_RPROC_CMA_SIZE_IPU1             0x02000000
#define DRA7_RPROC_CMA_SIZE_IPU2             0x05000000
#define DRA7_RPROC_CMA_SIZE_DSP1             0x02000000
#define DRA7_RPROC_CMA_SIZE_DSP2             0x02000000

#define DRA7_PGTBL_BASE_IPU1                 0xbfc00000
#define DRA7_PGTBL_BASE_IPU2                 0xbfc08000
#define DRA7_PGTBL_BASE_DSP1                 0xbfc10000
#define DRA7_PGTBL_BASE_DSP2                 0xbfc18000

/*
 * The memory for the page tables (256 KB per IPU) is placed just before
 * the carveout memories for the remote processors. 16 KB of memory is
 * needed for the L1 page table (4096 entries * 4 bytes per 1 MB section).
 * Any smaller page (64 KB or 4 KB) entries are supported through L2 page
 * tables (1 KB per table). The remaining 240 KB can provide support for
 * 240 L2 page tables. Any remoteproc firmware image requiring more than
 * 240 L2 page table entries would need more memory to be reserved.
 */
#define PAGE_TABLE_SIZE_L1 (0x00004000)
#define PAGE_TABLE_SIZE_L2 (0x400)
#define MAX_NUM_L2_PAGE_TABLES (240)
#define PAGE_TABLE_SIZE_L2_TOTAL (MAX_NUM_L2_PAGE_TABLES * PAGE_TABLE_SIZE_L2)
#define PAGE_TABLE_SIZE (PAGE_TABLE_SIZE_L1 + (PAGE_TABLE_SIZE_L2_TOTAL))

int get_l2_pg_tbl_addr(unsigned int virt, unsigned int *pg_tbl_addr);
int
config_l2_pagetable(unsigned int virt, unsigned int phys,
		    unsigned int pg_sz, unsigned int pg_tbl_addr);
unsigned int
ipu_config_pagetable(struct udevice *dev, unsigned int virt, unsigned int phys,
		     unsigned int len);
int load_firmware(char *name_fw, u32 *loadaddr);
void *alloc_mem(struct udevice *dev, unsigned long len, unsigned long align);

#endif //REMOTEPROC_TI_DRA7_RPROC_H
