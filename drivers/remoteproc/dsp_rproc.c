// SPDX-License-Identifier: GPL-2.0
/*
 * IPU remoteproc driver for various SoCs
 *
 * Copyright (C) 2019 Texas Instruments Incorporated - http://www.ti.com/
 *	Angela Stegmaier  <angelabaker@ti.com>
 *	Venkateswara Rao Mandela <venkat.mandela@ti.com>
 *      Keerthy <j-keerthy@ti.com>
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
#
#define IPU1_LOAD_ADDR         (0xa0fff000)
#define MAX_REMOTECORE_BIN_SIZE (8 * 0x100000)

enum dsp_num {
	DSP1= 0,
	DSP2,
	RPROC_END_ENUMS,
};

#define IPU2_LOAD_ADDR         (IPU1_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP1_LOAD_ADDR         (IPU2_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)
#define DSP2_LOAD_ADDR         (DSP1_LOAD_ADDR + MAX_REMOTECORE_BIN_SIZE)

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

#define DRA7_RPROC_CMA_BASE_IPU1             0x9d000000
#define DRA7_RPROC_CMA_BASE_IPU2             0x95800000
#define DRA7_RPROC_CMA_BASE_DSP1             0x99000000
#define DRA7_RPROC_CMA_BASE_DSP2             0x9f000000

#define DRA7_RPROC_CMA_SIZE_IPU1             0x02000000
#define DRA7_RPROC_CMA_SIZE_IPU2             0x03800000
#define DRA7_RPROC_CMA_SIZE_DSP1             0x04000000
#define DRA7_RPROC_CMA_SIZE_DSP2             0x00800000

#define DRA7_PGTBL_BASE_IPU1                 0x95700000
#define DRA7_PGTBL_BASE_IPU2                 0x95740000
#define DRA7_PGTBL_BASE_DSP1                 0x95780000
#define DRA7_PGTBL_BASE_DSP2                 0x957c0000

#define NUM_DSP_MEMORIES                     3
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
void *ipu_alloc_mem(struct udevice *dev, unsigned long len, unsigned long align);

struct rproc *dsp_rproc_cfg_arr[RPROC_END_ENUMS] ;
/**
 * struct omap_rproc_mem - internal memory structure
 * @cpu_addr: MPU virtual address of the memory region
 * @bus_addr: bus address used to access the memory region
 * @dev_addr: device address of the memory region from DSP view
 * @size: size of the memory region
 */

struct dsp_rproc_mem {
	void __iomem *cpu_addr;
	phys_addr_t bus_addr;
	u32 dev_addr;
	size_t size;
};

struct dsp_privdata {
	struct dsp_rproc_mem mem[NUM_DSP_MEMORIES];
	struct list_head mappings;
	const char *fw_name;
	u32 bootaddr;
	int id;
	struct udevice *rdev;
};

typedef int (*handle_resource_t) (void *, int offset, int avail);

extern unsigned int *page_table_l1;
extern unsigned int *page_table_l2;
/*
 * Set maximum carveout size to 96 MB
 */
#define DRA7_RPROC_MAX_CMA_SIZE (96 * 0x100000)

/*
 * These global variables are used for deriving the MMU page tables. They
 * are initialized for each core with the appropriate values. The length
 * of the array mem_bitmap is set as per a 96 MB carveout which the
 * maximum set aside in the current memory map.
 */
extern unsigned long mem_base;
extern unsigned long mem_size;
extern unsigned long

mem_bitmap[BITS_TO_LONGS(DRA7_RPROC_MAX_CMA_SIZE >> PAGE_SHIFT)];
extern unsigned long mem_count;

extern unsigned int pgtable_l2_map[MAX_NUM_L2_PAGE_TABLES];
extern unsigned int pgtable_l2_cnt;

/******************************************************************************
 * dpll_lock_sequence() : DPLL lock sequence
 *****************************************************************************/
void dpll_lock_sequence(u32 base_address)
{
	int timer = DPLL_TIMEOUT;
	u32 reg = 0;

	reg = __raw_readl(base_address);

	/* Enable the DPLL lock mode. The bit field is 3 bits long.
	 * So not clearing the bit field before setting it.
	 */
	reg = (reg | 0x7);

	/* Put DPLL into lock mode */
	__raw_writel(reg, base_address);

	/* Wait for DPLL to be locked */
	while (((__raw_readl(base_address + 0x4) & 0x1) != 0x1) && (timer--));

	if (timer <= 0)
		printf("\tERROR: timeout while locking DPLL\n");
}

/******************************************************************************
 * dpll_unlock_sequence() : DPLL unlock sequence
 *****************************************************************************/
void dpll_unlock_sequence(u32 base_address)
{
	u32 reg = 0;

	reg = __raw_readl(base_address);

	/* Take DPLL out of lock mode */
	__raw_writel((reg & (~0x1)), base_address);
}

/* Configuring to 600 MHz DSP with 20 MHz sys_clk.
 * Code based on the DRA7xx_prcm_config.gel
 */
u32 dsp_enable_dpll(void)
{
	static u32 dpll_do_init = 1;
	u32 dpll_m = 150;
	u32 dpll_n = 4;
	u32 divm2 = 1;
	u32 dpll_base_addr = CM_CLKMODE_DPLL_DSP;

	/* return if the DPLL is already configured */
	if (dpll_do_init == 0) {
		debug("DSP DPLL configuration already configured\n");
		return 0;
	}

	/* We are assuming that the DPLL is unlocked and
	   we do not need to unlock it.
	 */

	debug("DSP DPLL configuration in progress\n");

	if (__raw_readl(dpll_base_addr + 0x4) & 0x1) {
		debug("DSP DPLL already locked, now unlocking....\n");
		dpll_unlock_sequence(dpll_base_addr);
	}

	__raw_writel(((dpll_m << 8) | dpll_n), dpll_base_addr + 0x0C);
	__raw_writel(divm2, dpll_base_addr + 0x10);

	/* CM_DIV_M3_DPLL - not used in default configuration */
	/* Output of M3 divider can be routed to EVE if required */
	__raw_writel(0x3, dpll_base_addr + 0x14);

	dpll_lock_sequence(dpll_base_addr);

	debug("DSP DPLL configuration is DONE!\n");
	dpll_do_init = 0;

	return 0;
}

u32 dsp_start_core(u32 core_id, struct rproc *cfg)
{
	u32 prm_base = 0;
	u32 boot_addr = 0;
	u32 ret = 1;

	if (core_id == DSP1) {
		prm_base = DSP1_PRM_BASE;
		boot_addr = DSP1_BOOTADDR;
		ret = 0;
	} else if (core_id == DSP2) {
		prm_base = DSP2_PRM_BASE;
		boot_addr = DSP2_BOOTADDR;
		ret = 0;
	}

	if (ret == 0) {
		u32 boot_reg = 0;

		/* Configure the DSP entry point */
		/* DSP boots from CTRL_CORE_CONTROL_DSP1_RST_VECTOR */
		/* Boot address is shifted by 10 bits before begin written */
		boot_reg = __raw_readl(boot_addr);
		boot_reg = (boot_reg & (~DRA7XX_CTRL_CORE_DSP_RST_VECT_MASK));
		boot_reg =
		    (boot_reg |
		     ((cfg->
		       entry_point >> 10) &
		      DRA7XX_CTRL_CORE_DSP_RST_VECT_MASK));

		__raw_writel(boot_reg, boot_addr);

		/* bring the DSP out of reset */
		__raw_writel(0x0, prm_base + 0x10);

		/* check module is functional or not */
		while (((__raw_readl(prm_base + 0x14) & 0x3) != 0x3));
		ret = 0;
	}

	return ret;
}

u32 dsp_start_clocks(u32 core_id, struct rproc *cfg)
{
	u32 reg = 0;
	u32 timer_reg = 0;
	u32 dsp_clkstctrl = 0;
	u32 prm_base = 0;
	u32 mmu_config = 0;
	u32 wdt_ctrl = 0;

	if ((core_id != DSP1) && (core_id != DSP2))
		return 1;

	debug("DSP initialization in progress\n");

	/* Configure the DSP PLL */
	dsp_enable_dpll();

	if (core_id == DSP1) {
		/* Enable Timer 5 for DSP1 */
		timer_reg = CM_IPU_TIMER5_CLKCTRL;
		prm_base = DSP1_PRM_BASE;
		dsp_clkstctrl = CM_DSP1_CLKSTCTRL;
		mmu_config = DSP1_SYS_MMU_CONFIG;
		wdt_ctrl = CM_L4PER_TIMER10_CLKCTRL;

	} else {
		/* Enable Timer 6 for DSP2 */
		timer_reg = CM_IPU_TIMER6_CLKCTRL;
		prm_base = DSP2_PRM_BASE;
		dsp_clkstctrl = CM_DSP2_CLKSTCTRL;
		mmu_config = DSP2_SYS_MMU_CONFIG;
	}

	/* Using TIMER_SYS_CLK as the clock source */
	reg = __raw_readl(timer_reg);
	__raw_writel((reg & ~0x0F000003) | 0x00000002, timer_reg);
	debug("Enabled SysBIOS Tick Timer\n");

	/* Enable the watchdog timer */
	if (wdt_ctrl != 0) {
		/*
		 * Using SYS_CLK1_32K_CLK as the clock source for the
		 * watch dog timers. DSP will eventually configure
		 * these timers with the right clock source. If we use
		 * a higher frequency clock as the clock source, the
		 * timer will overflow and trigger a watchdog interrupt
		 * even before the kernel has a chance to connect to
		 * DSP.
		 */
		reg = __raw_readl(wdt_ctrl);
		__raw_writel((reg & ~0x0F000003) | 0x01000002,
			     wdt_ctrl);
	}

	/* Enable the DSP Clock domain in SW Wkup */
	__raw_writel(0x2, dsp_clkstctrl);

	/* Enable DSP and check that the clock is gated in the clock domain
	   register */
	__raw_writel(0x1, dsp_clkstctrl + 0x20);
	while ((__raw_readl(dsp_clkstctrl) & 0x100) != 0x100);
	debug("DSP Clock enabled and gated in domain controller\n");

	/*
	 * Clear the prm status bits before bringing the core out of reset.
	 * This will prevent the below status checks from passing prematurely
	 * if the DSP core was powered on and off earlier in U-Boot.
	 * The register is write '1' to clear a bit. */
	__raw_writel(0x3, prm_base + 0x14);

	/*
	 * Enable RESET for the DSP MMU, cache and slave interface and
	 * DSP local reset. This may not be necessary since the reset value
	 * is the same.*/
	__raw_writel(0x3, prm_base + 0x10);

	/* Bring the MMU, cache and reset interface out of reset */
	__raw_writel(0x1, prm_base + 0x10);

	/*
	 * Check that the reset state reflects correctly in the status
	 * register.
	 */
	while ((__raw_readl(prm_base + 0x14) & 0x2) != 0x2);
	debug("DSP MMU out of reset\n");

	/* Enable the DSP1 SDMA and MDMA accesses to pass through the MMU */
	if (cfg->has_rsc_table)
		__raw_writel(0x11, mmu_config);

	/* At this point, the DSP MMU can be configured. */

	debug("DSP ready for MMU configuration and code loading\n");

	return 0;
}


u32 dsp_config_mmu(u32 core_id, struct rproc *cfg)
{
	u32 i = 0;
	u32 reg = 0;
	/*
	 * Clear the entire pagetable location before programming the
	 * address into the MMU
	 */
	memset((void *)cfg->page_table_addr, 0x00, PAGE_TABLE_SIZE);

	for (i = 0; i < cfg->num_iommus; i++) {
		u32 mmu_base = cfg->mmu_base_addr[i];

		__raw_writel((int)cfg->page_table_addr, mmu_base + 0x4c);
		reg = __raw_readl(mmu_base + 0x88);

		/*
		 * enable bus-error back
		 */
		__raw_writel(reg | 0x1, mmu_base + 0x88);

		/*
		 * Enable the MMU IRQs during MMU programming for the
		 * late attachcase. This is to allow the MMU fault to be
		 * detected by the kernel.
		 *
		 * MULTIHITFAULT|EMMUMISS|TRANSLATIONFAULT|TABLEWALKFAULT
		 */
		__raw_writel(0x1E, mmu_base + 0x1c);

		/*
		 * emutlbupdate|TWLENABLE|MMUENABLE
		 */
		__raw_writel(0x6, mmu_base + 0x44);
	}

	return 0;
}
/**
 * enum ipu_mem - PRU core memory range identifiers
 */
enum dsp_mem {
	PRU_MEM_IRAM = 0,
	PRU_MEM_CTRL,
	PRU_MEM_DEBUG,
	PRU_MEM_MAX,
};

int da_to_pa_dsp(struct udevice *dev, int da)
{
	struct rproc_mem_entry *maps = NULL;
	struct dsp_privdata *priv = dev_get_priv(dev);

	list_for_each_entry(maps, &priv->mappings, node) {
		if (da >= maps->da && da < (maps->da + maps->len))
			return maps->dma + (da - maps->da);
	}

	return 0;
}
static int dsp_start(struct udevice *dev)
{
	struct dsp_privdata *priv;
	struct rproc *cfg = NULL;
	ulong addr;

	priv = dev_get_priv(dev);

	cfg = dsp_rproc_cfg_arr[priv->id];
	if (cfg->config_peripherals)
		cfg->config_peripherals(priv->id, cfg);

	addr = (priv->id == DSP1) ? DSP1_LOAD_ADDR : DSP2_LOAD_ADDR;

	cfg->entry_point = rproc_elf_get_boot_addr(dev, addr);

	/* Start running the remote core */
	if (cfg->start_core)
	       cfg->start_core(priv->id, cfg);

	return 0;
}

static int dsp_stop(struct udevice *dev)
{
	return 0;
}

/**
 * ipu_init() - Initialize the remote processor
 * @dev:	rproc device pointer
 *
 * Return: 0 if all went ok, else return appropriate error
 */
static int dsp_init(struct udevice *dev)
{
	return 0;
}

static int dsp_add_res(struct udevice *dev, struct rproc_mem_entry *mapping)
{
	struct dsp_privdata *priv = dev_get_priv(dev);

	list_add_tail(&mapping->node, &priv->mappings);
	return 0;
}

static int dsp_load(struct udevice *dev, ulong addr, ulong size)
{
	Elf32_Ehdr *ehdr;	/* Elf header structure pointer */
	Elf32_Phdr *phdr;	/* Program header structure pointer */
	Elf32_Phdr proghdr;
	struct resource_table *ptable = NULL;
	int va;
	int pa;
	int i;

	ehdr = (Elf32_Ehdr *)addr;
	phdr = (Elf32_Phdr *)(addr + ehdr->e_phoff);
	/*
	 * Load each program header
	 */
	for (i = 0; i < ehdr->e_phnum; ++i) {
		memcpy(&proghdr, phdr, sizeof(Elf32_Phdr));

		if (proghdr.p_type != PT_LOAD) {
			++phdr;
			continue;
		}

		va = proghdr.p_paddr;
		pa = da_to_pa_dsp(dev, va);
		if (pa)
			proghdr.p_paddr = pa;

		void *dst = (void *)(uintptr_t)proghdr.p_paddr;
		void *src = (void *)addr + proghdr.p_offset;

		debug("Loading phdr %i to 0x%p (%i bytes)\n", i, dst,
		      proghdr.p_filesz);
		if (proghdr.p_filesz)
			memcpy(dst, src, proghdr.p_filesz);
		/*
		 * TODO: This line needs to be removed after test
		 */
		if (!ptable) {
			if (proghdr.p_filesz != proghdr.p_memsz &&
			    (proghdr.p_paddr - 0x58820000) > 0x4000 &&
			     proghdr.p_memsz > 9)
				memset(dst + proghdr.p_filesz, 0x00,
				       proghdr.p_memsz - proghdr.p_filesz);
		} else {
			if (proghdr.p_filesz != proghdr.p_memsz)
				memset(dst + proghdr.p_filesz, 0x00,
				       proghdr.p_memsz - proghdr.p_filesz);
		}

		flush_cache((unsigned long)dst, proghdr.p_memsz);

		++phdr;
	}

	return 0;
}

static const struct dm_rproc_ops dsp_ops = {
	.init = dsp_init,
	.start = dsp_start,
	.stop = dsp_stop,
	.load = dsp_load,
	.add_res = dsp_add_res,
	.config_pagetable = ipu_config_pagetable,
	.alloc_mem = ipu_alloc_mem,
};

/*
 * If the remotecore binary expects any peripherals to be setup before it has
 * booted, configure them here.
 *
 * These functions are left empty by default as their operation is usecase
 * specific.
 */
u32 dsp1_config_peripherals(u32 core_id, struct rproc *cfg)
{
	u32 reg;
	u32 timer_reg = 0;

	/* Enable Timer 6 used as timestamp provider for DSP1 */
	timer_reg = CM_IPU_TIMER6_CLKCTRL;
	reg = __raw_readl(timer_reg);
	__raw_writel((reg & ~0x0F000003) | 0x00000002, timer_reg);

	return 0;
}

u32 dsp2_config_peripherals(u32 core_id, struct rproc *cfg)
{
	u32 reg;
	u32 timer_reg = 0;

	timer_reg = CM_IPU_TIMER5_CLKCTRL;
	reg = __raw_readl(timer_reg);
	__raw_writel((reg & ~0x0F000003) | 0x00000002, timer_reg);

	return 0;
}

struct rproc_intmem_to_l3_mapping dsp1_intmem_to_l3_mapping = {
	.num_entries = 3,
	.mappings = {
		/* L2 SRAM */
		{
			.priv_addr = 0x00800000,
			.l3_addr = 0x40800000,
			.len = (288*1024)
		},
		/* L1P SRAM */
		{
			.priv_addr = 0x00E00000,
			.l3_addr = 0x40E00000,
			.len = (32*1024)
		},
		/* L1D SRAM */
		{
			.priv_addr = 0x00F00000,
			.l3_addr = 0x40F00000,
			.len = (32*1024)
		},
	}
};

struct rproc_intmem_to_l3_mapping dsp2_intmem_to_l3_mapping = {
	.num_entries = 3,
	.mappings = {
		/* L2 SRAM */
		{
			.priv_addr = 0x00800000,
			.l3_addr = 0x41000000,
			.len = (288*1024)
		},
		/* L1P SRAM */
		{
			.priv_addr = 0x00E00000,
			.l3_addr = 0x41600000,
			.len = (32*1024)
		},
		/* L1D SRAM */
		{
			.priv_addr = 0x00F00000,
			.l3_addr = 0x41700000,
			.len = (32*1024)
		},
	}
};

struct rproc dsp1_config = {
	.num_iommus = 2,
	.cma_base = DRA7_RPROC_CMA_BASE_DSP1,
	.cma_size = DRA7_RPROC_CMA_SIZE_DSP1,
	.page_table_addr = DRA7_PGTBL_BASE_DSP1,
	.mmu_base_addr = {0x40D01000, 0x40D02000},
	.load_addr = DSP1_LOAD_ADDR,
	.core_name = "DSP1",
	.firmware_name = "dra7-dsp1-fw.xe66",
	.start_clocks = dsp_start_clocks,
	.start_core = dsp_start_core,
	.config_mmu = dsp_config_mmu,
	.config_peripherals = dsp1_config_peripherals,
	.intmem_to_l3_mapping = &dsp1_intmem_to_l3_mapping
};

struct rproc dsp2_config = {
	.num_iommus = 2,
	.cma_base = DRA7_RPROC_CMA_BASE_DSP2,
	.cma_size = DRA7_RPROC_CMA_SIZE_DSP2,
	.page_table_addr = DRA7_PGTBL_BASE_DSP2,
	.mmu_base_addr = {0x41501000, 0x41502000},
	.load_addr = DSP2_LOAD_ADDR,
	.core_name = "DSP2",
	.firmware_name = "dra7-dsp2-fw.xe66",
	.start_clocks = dsp_start_clocks,
	.start_core = dsp_start_core,
	.config_mmu = dsp_config_mmu,
	.config_peripherals = dsp2_config_peripherals,
	.intmem_to_l3_mapping = &dsp2_intmem_to_l3_mapping
};

struct rproc *dsp_rproc_cfg_arr[RPROC_END_ENUMS] = {
	[DSP2] = &dsp2_config,
	[DSP1] = &dsp1_config
};

u32 spl_pre_boot_dsp_core(struct udevice *dev, u32 core_id)
{
	struct rproc *cfg = NULL;
	unsigned long load_elf_status = 0;
	int tablesz;

	cfg = dsp_rproc_cfg_arr[core_id];
	/*
	 * Check for valid elf image
	 */
	if (!valid_elf_image(cfg->load_addr))
		return 1;

	if (rproc_find_resource_table(dev, cfg->load_addr, &tablesz))
		cfg->has_rsc_table = 1;
	else
		cfg->has_rsc_table = 0;

	/* Clock the remote core */
	if (cfg->start_clocks)
		cfg->start_clocks(core_id, cfg);
	/*
	 * Configure the MMU
	 */
	if (cfg->config_mmu && cfg->has_rsc_table)
		cfg->config_mmu(core_id, cfg);

	/*
	 * Load the remote core. Fill the page table of the first(possibly
	 * only) IOMMU during ELF loading.  Copy the page table to the second
	 * IOMMU before running the remote core.
	 */

	page_table_l1 = (unsigned int *)cfg->page_table_addr;
	page_table_l2 =
	    (unsigned int *)(cfg->page_table_addr + PAGE_TABLE_SIZE_L1);
	mem_base = cfg->cma_base;
	mem_size = cfg->cma_size;
	memset(mem_bitmap, 0x00, sizeof(mem_bitmap));
	mem_count = (cfg->cma_size >> PAGE_SHIFT);

	/*
	 * Clear variables used for level 2 page table allocation
	 */
	memset(pgtable_l2_map, 0x00, sizeof(pgtable_l2_map));
	pgtable_l2_cnt = 0;

	load_elf_status = rproc_parse_resource_table(dev, cfg);
	if (load_elf_status == 0) {
		printf("load_elf_image_phdr returned error for core %s\n",
		      cfg->core_name);
		return 1;
	}

	flush_cache(cfg->page_table_addr, PAGE_TABLE_SIZE);

	return 0;
}

/**
 * dsp_probe() - Basic probe
 * @dev:	corresponding k3 remote processor device
 *
 * Return: 0 if all goes good, else appropriate error message.
 */
static int dsp_probe(struct udevice *dev)
{
	struct dsp_privdata *dsp;
	static const char *const mem_names[] = { "l2ram", "l1pram", "l1dram" };
	int size = 0, num_mems;
	struct rproc *cfg = NULL;
	u32 loadaddr = 0;
	int i;
	int ret = 0;

	dsp = dev_get_priv(dev);
	num_mems = ARRAY_SIZE(mem_names);

	if (devfdt_get_addr(dev) == 0x40800000)
		dsp->id = DSP1;
	else
		dsp->id = DSP2;

	for (i = 0; i < num_mems; i++) {
		dsp->mem[i].bus_addr =
		devfdt_get_addr_size_name(dev, mem_names[i],
					  (fdt_addr_t *)&dsp->mem[i].size);
		if (dsp->mem[i].bus_addr == FDT_ADDR_T_NONE) {
			dev_err(dev, "%s bus address not found\n",
				mem_names[i]);
			return -EINVAL;
		}
		dsp->mem[i].cpu_addr = map_physmem(dsp->mem[i].bus_addr,
						   dsp->mem[i].size,
						   MAP_NOCACHE);
		dsp->mem[i].dev_addr = dsp->mem[i].bus_addr &
					MAP_NOCACHE;

		dev_info(dev, "ID %d memory %8s: bus addr %pa size 0x%zx va %p da 0x%x\n",
			dsp->id, mem_names[i], &dsp->mem[i].bus_addr,
			dsp->mem[i].size, dsp->mem[i].cpu_addr,
			dsp->mem[i].dev_addr);
	}

	cfg = dsp_rproc_cfg_arr[dsp->id];
	loadaddr = cfg->load_addr;
	size = load_firmware(cfg->firmware_name, &loadaddr);
	if (!size) {
		dev_err(dev, "Firmware loading failed\n");
		return -EINVAL;
	}

	INIT_LIST_HEAD(&dsp->mappings);
	ret = spl_pre_boot_dsp_core(dev, dsp->id);

	return ret;
}

static const struct udevice_id dsp_ids[] = {
	{.compatible = "ti,dra7-dsp"},
	{}
};

U_BOOT_DRIVER(dsp) = {
	.name = "dsp",
	.of_match = dsp_ids,
	.id = UCLASS_REMOTEPROC,
	.ops = &dsp_ops,
	.probe = dsp_probe,
	.priv_auto_alloc_size = sizeof(struct dsp_privdata),
};
