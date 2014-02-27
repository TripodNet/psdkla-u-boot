/*
 * Copyright (c) 2001 William L. Pitts
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are freely
 * permitted provided that the above copyright notice and this
 * paragraph and the following disclaimer are duplicated in all
 * such forms.
 *
 * This software is provided "AS IS" and without any express or
 * implied warranties, including, without limitation, the implied
 * warranties of merchantability and fitness for a particular
 * purpose.
 */

#include <common.h>
#include <command.h>
#include <errno.h>
#include <linux/compat.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <malloc.h>
#include <net.h>
#include <elf.h>
#include <vxworks.h>

#ifdef CONFIG_IPU_RESOURCE_TABLE_MAPPING
#include "remoteproc.h"
#endif

#if defined(CONFIG_WALNUT) || defined(CONFIG_SYS_VXWORKS_MAC_PTR)
DECLARE_GLOBAL_DATA_PTR;
#endif

unsigned long load_elf_image_phdr(unsigned long addr);

/* ======================================================================
 * Determine if a valid ELF image exists at the given memory location.
 * First looks at the ELF header magic field, the makes sure that it is
 * executable and makes sure that it is for a PowerPC.
 * ====================================================================== */
int valid_elf_image(unsigned long addr)
{
	Elf32_Ehdr *ehdr;		/* Elf header structure pointer */

	/* -------------------------------------------------- */

	ehdr = (Elf32_Ehdr *) addr;

	if (!IS_ELF(*ehdr)) {
		printf("## No elf image at address 0x%08lx\n", addr);
		return 0;
	}

	if (ehdr->e_type != ET_EXEC) {
		printf("## Not a 32-bit elf image at address 0x%08lx\n", addr);
		return 0;
	}

#if 0
	if (ehdr->e_machine != EM_PPC) {
		printf("## Not a PowerPC elf image at address 0x%08lx\n", addr);
		return 0;
	}
#endif

	return 1;
}

#ifndef CONFIG_SPL_BUILD
static unsigned long load_elf_image_shdr(unsigned long addr);

/* Allow ports to override the default behavior */
__attribute__((weak))
unsigned long do_bootelf_exec(ulong (*entry)(int, char * const[]),
			       int argc, char * const argv[])
{
	unsigned long ret;

	/*
	 * QNX images require the data cache is disabled.
	 * Data cache is already flushed, so just turn it off.
	 */
	int dcache = dcache_status();
	if (dcache)
		dcache_disable();

	/*
	 * pass address parameter as argv[0] (aka command name),
	 * and all remaining args
	 */
	ret = entry(argc, argv);

	if (dcache)
		dcache_enable();

	return ret;
}

/* ======================================================================
 * Interpreter command to boot an arbitrary ELF image from memory.
 * ====================================================================== */
int do_bootelf(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	unsigned long addr;		/* Address of the ELF image     */
	unsigned long rc;		/* Return value from user code  */
	char *sload, *saddr;

	/* -------------------------------------------------- */
	int rcode = 0;

	sload = saddr = NULL;
	if (argc == 3) {
		sload = argv[1];
		saddr = argv[2];
	} else if (argc == 2) {
		if (argv[1][0] == '-')
			sload = argv[1];
		else
			saddr = argv[1];
	}

	if (saddr)
		addr = simple_strtoul(saddr, NULL, 16);
	else
		addr = load_addr;

	if (!valid_elf_image(addr))
		return 1;

	if (sload && sload[1] == 'p')
		addr = load_elf_image_phdr(addr);
	else
		addr = load_elf_image_shdr(addr);

	printf("## Starting application at 0x%08lx ...\n", addr);

	/*
	 * pass address parameter as argv[0] (aka command name),
	 * and all remaining args
	 */
	rc = do_bootelf_exec((void *)addr, argc - 1, argv + 1);
	if (rc != 0)
		rcode = 1;

	printf("## Application terminated, rc = 0x%lx\n", rc);
	return rcode;
}

/* ======================================================================
 * Interpreter command to boot VxWorks from a memory image.  The image can
 * be either an ELF image or a raw binary.  Will attempt to setup the
 * bootline and other parameters correctly.
 * ====================================================================== */
int do_bootvx(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	unsigned long addr;		/* Address of image            */
	unsigned long bootaddr;	/* Address to put the bootline */
	char *bootline;			/* Text of the bootline        */
	char *tmp;			/* Temporary char pointer      */
	char build_buf[128];		/* Buffer for building the bootline */

	/* ---------------------------------------------------
	 *
	 * Check the loadaddr variable.
	 * If we don't know where the image is then we're done.
	 */

	if (argc < 2)
		addr = load_addr;
	else
		addr = simple_strtoul(argv[1], NULL, 16);

#if defined(CONFIG_CMD_NET)
	/*
	 * Check to see if we need to tftp the image ourselves before starting
	 */
	if ((argc == 2) && (strcmp(argv[1], "tftp") == 0)) {
		if (NetLoop(TFTPGET) <= 0)
			return 1;
		printf("Automatic boot of VxWorks image at address 0x%08lx ...\n",
			addr);
	}
#endif

	/* This should equate
	 * to NV_RAM_ADRS + NV_BOOT_OFFSET + NV_ENET_OFFSET
	 * from the VxWorks BSP header files.
	 * This will vary from board to board
	 */

#if defined(CONFIG_WALNUT)
	tmp = (char *) CONFIG_SYS_NVRAM_BASE_ADDR + 0x500;
	eth_getenv_enetaddr("ethaddr", (uchar *)build_buf);
	memcpy(tmp, &build_buf[3], 3);
#elif defined(CONFIG_SYS_VXWORKS_MAC_PTR)
	tmp = (char *) CONFIG_SYS_VXWORKS_MAC_PTR;
	eth_getenv_enetaddr("ethaddr", (uchar *)build_buf);
	memcpy(tmp, build_buf, 6);
#else
	puts("## Ethernet MAC address not copied to NV RAM\n");
#endif

	/*
	 * Use bootaddr to find the location in memory that VxWorks
	 * will look for the bootline string. The default value for
	 * PowerPC is LOCAL_MEM_LOCAL_ADRS + BOOT_LINE_OFFSET which
	 * defaults to 0x4200
	 */
	tmp = getenv("bootaddr");
	if (!tmp)
		bootaddr = CONFIG_SYS_VXWORKS_BOOT_ADDR;
	else
		bootaddr = simple_strtoul(tmp, NULL, 16);

	/*
	 * Check to see if the bootline is defined in the 'bootargs'
	 * parameter. If it is not defined, we may be able to
	 * construct the info
	 */
	bootline = getenv("bootargs");
	if (bootline) {
		memcpy((void *) bootaddr, bootline,
			max(strlen(bootline), 255));
		flush_cache(bootaddr, max(strlen(bootline), 255));
	} else {
		sprintf(build_buf, CONFIG_SYS_VXWORKS_BOOT_DEVICE);
		tmp = getenv("bootfile");
		if (tmp)
			sprintf(&build_buf[strlen(build_buf)],
				 "%s:%s ", CONFIG_SYS_VXWORKS_SERVERNAME, tmp);
		else
			sprintf(&build_buf[strlen(build_buf)],
				 "%s:file ", CONFIG_SYS_VXWORKS_SERVERNAME);

		tmp = getenv("ipaddr");
		if (tmp)
			sprintf(&build_buf[strlen(build_buf)], "e=%s ", tmp);

		tmp = getenv("serverip");
		if (tmp)
			sprintf(&build_buf[strlen(build_buf)], "h=%s ", tmp);

		tmp = getenv("hostname");
		if (tmp)
			sprintf(&build_buf[strlen(build_buf)], "tn=%s ", tmp);

#ifdef CONFIG_SYS_VXWORKS_ADD_PARAMS
		sprintf(&build_buf[strlen(build_buf)],
			 CONFIG_SYS_VXWORKS_ADD_PARAMS);
#endif

		memcpy((void *) bootaddr, build_buf,
			max(strlen(build_buf), 255));
		flush_cache(bootaddr, max(strlen(build_buf), 255));
	}

	/*
	 * If the data at the load address is an elf image, then
	 * treat it like an elf image. Otherwise, assume that it is a
	 * binary image
	 */

	if (valid_elf_image(addr)) {
		addr = load_elf_image_shdr(addr);
	} else {
		puts("## Not an ELF image, assuming binary\n");
		/* leave addr as load_addr */
	}

	printf("## Using bootline (@ 0x%lx): %s\n", bootaddr,
			(char *) bootaddr);
	printf("## Starting vxWorks at 0x%08lx ...\n", addr);

	dcache_disable();
	((void (*)(int)) addr) (0);

	puts("## vxWorks terminated\n");
	return 1;
}
#endif

#ifdef CONFIG_IPU_RESOURCE_TABLE_MAPPING
static struct resource_table *table;
static struct list_head mappings;

typedef int (*handle_resource_t)(void *, int offset, int avail);

void *alloc_mem(unsigned long len, unsigned long align);
unsigned int config_pagetable(unsigned int virt, unsigned int phys,
                              unsigned int len);

int va_to_pa(int va)
{
	struct mem_entry *maps = NULL;

	list_for_each_entry(maps, &mappings, node) {
		if (va >= maps->da && va < (maps->da + maps->len)) {
			return maps->dma + (va - maps->da);
		}
	}

	return 0;
}


static int handle_trace(struct fw_rsc_trace *rsc, int offset, int avail)
{
	if (sizeof(*rsc) > avail) {
		printf("trace rsc is truncated\n");
		return -EINVAL;
	}

	/* make sure reserved bytes are zeroes */
	if (rsc->reserved) {
		printf("trace rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	debug("trace rsc: da 0x%x, len 0x%x\n", rsc->da, rsc->len);

	return 0;
}

static int handle_devmem(struct fw_rsc_devmem *rsc, int offset, int avail)
{
	struct mem_entry *mapping;

	if (sizeof(*rsc) > avail) {
		printf("devmem rsc is truncated\n");
		return -EINVAL;
	}

	/* make sure reserved bytes are zeroes */
	if (rsc->reserved) {
		printf("devmem rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	debug("devmem rsc: pa 0x%x, da 0x%x, len 0x%x\n",
					rsc->pa, rsc->da, rsc->len);

	config_pagetable(rsc->da, rsc->pa, rsc->len);

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping) {
		printf("kzalloc mapping failed\n");
		return -ENOMEM;
	}

	/*
	 * We'll need this info later when we'll want to unmap everything
	 * (e.g. on shutdown).
	 *
	 * We can't trust the remote processor not to change the resource
	 * table, so we must maintain this info independently.
	 */
	mapping->dma = rsc->pa;
	mapping->da = rsc->da;
	mapping->len = rsc->len;
	list_add_tail(&mapping->node, &mappings);

	debug("mapped devmem pa 0x%x, da 0x%x, len 0x%x\n",
					rsc->pa, rsc->da, rsc->len);

	return 0;
}

static int handle_carveout(struct fw_rsc_carveout *rsc, int offset, int avail)
{
	struct mem_entry *mapping;

	if (sizeof(*rsc) > avail) {
		printf("carveout rsc is truncated\n");
		return -EINVAL;
	}

	/* make sure reserved bytes are zeroes */
	if (rsc->reserved) {
		printf("carveout rsc has non zero reserved bytes\n");
		return -EINVAL;
	}

	debug("carveout rsc: da %x, pa %x, len %x, flags %x\n",
			rsc->da, rsc->pa, rsc->len, rsc->flags);

	rsc->pa = (int)alloc_mem(rsc->len, 8);
	config_pagetable(rsc->da, rsc->pa, rsc->len);

	/*
	 * Ok, this is non-standard.
	 *
	 * Sometimes we can't rely on the generic iommu-based DMA API
	 * to dynamically allocate the device address and then set the IOMMU
	 * tables accordingly, because some remote processors might
	 * _require_ us to use hard coded device addresses that their
	 * firmware was compiled with.
	 *
	 * In this case, we must use the IOMMU API directly and map
	 * the memory to the device address as expected by the remote
	 * processor.
	 *
	 * Obviously such remote processor devices should not be configured
	 * to use the iommu-based DMA API: we expect 'dma' to contain the
	 * physical address in this case.
	 */
	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping) {
		printf("kzalloc mapping failed\n");
		return -ENOMEM;
	}

	/*
	 * We'll need this info later when we'll want to unmap
	 * everything (e.g. on shutdown).
	 *
	 * We can't trust the remote processor not to change the
	 * resource table, so we must maintain this info independently.
	 */
	mapping->dma = rsc->pa;
	mapping->da = rsc->da;
	mapping->len = rsc->len;
	list_add_tail(&mapping->node, &mappings);

	debug("carveout mapped 0x%x to 0x%x\n", rsc->da, rsc->pa);

	return 0;
}

/*
 * A lookup table for resource handlers. The indices are defined in
 * enum fw_resource_type.
 */
static handle_resource_t loading_handlers[RSC_LAST] = {
	[RSC_CARVEOUT] = (handle_resource_t)handle_carveout,
	[RSC_DEVMEM] = (handle_resource_t)handle_devmem,
	[RSC_TRACE] = (handle_resource_t)handle_trace,
	[RSC_VDEV] = NULL, /* VDEVs were handled upon registration */
};

/* handle firmware resource entries before booting the remote processor */
static int handle_resources(int len, handle_resource_t handlers[RSC_LAST])
{
	handle_resource_t handler;
	int ret = 0, i;
	void *pa;

	pa = alloc_mem(0x3000, 2);
	debug("dummy alloc_mem(0x3000, 2) for vring = %p\n", pa);
	pa = alloc_mem(0x3000, 2);
	debug("dummy alloc_mem(0x3000, 2) for vring = %p\n", pa);

	for (i = 0; i < table->num; i++) {
		int offset = table->offset[i];
		struct fw_rsc_hdr *hdr = (void *)table + offset;
		int avail = len - offset - sizeof(*hdr);
		void *rsc = (void *)hdr + sizeof(*hdr);

		/* make sure table isn't truncated */
		if (avail < 0) {
			printf("rsc table is truncated\n");
			return -EINVAL;
		}

		debug("rsc: type %d\n", hdr->type);

		if (hdr->type >= RSC_LAST) {
			printf("unsupported resource %d\n", hdr->type);
			continue;
		}

		handler = handlers[hdr->type];
		if (!handler)
			continue;

		ret = handler(rsc, offset + sizeof(*hdr), avail);
		if (ret)
			break;
	}

	return ret;
}

static Elf32_Shdr *
find_table(unsigned int addr)
{
	Elf32_Ehdr *ehdr;               /* Elf header structure pointer     */
	Elf32_Shdr *shdr;               /* Section header structure pointer */
	Elf32_Shdr sectionheader;
	int i;
	u8 *elf_data;
	char *name_table;
	struct resource_table *ptable;

	ehdr = (Elf32_Ehdr *)addr;
	elf_data = (u8 *)ehdr;
	shdr = (Elf32_Shdr *)(elf_data + ehdr->e_shoff);
	memcpy(&sectionheader, &shdr[ehdr->e_shstrndx], sizeof (sectionheader));
	name_table = (char *)(elf_data + sectionheader.sh_offset);

	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		memcpy(&sectionheader, shdr, sizeof (sectionheader));
		u32 size = sectionheader.sh_size;
		u32 offset = sectionheader.sh_offset;

		if (strcmp(name_table + sectionheader.sh_name,
				".resource_table"))
			continue;

		ptable = (struct resource_table *)(elf_data + offset);

		/* make sure table has at least the header */
		if (sizeof(struct resource_table) > size) {
			printf("header-less resource table\n");
			return NULL;
		}

		/* we don't support any version beyond the first */
		if (ptable->ver != 1) {
			printf("unsupported fw ver: %d\n", ptable->ver);
			return NULL;
		}

		/* make sure reserved bytes are zeroes */
		if (ptable->reserved[0] || ptable->reserved[1]) {
			printf("non zero reserved bytes\n");
			return NULL;
		}

		/* make sure the offsets array isn't truncated */
		if (ptable->num * sizeof(ptable->offset[0]) +
			sizeof(struct resource_table) > size) {
			printf("resource table incomplete\n");
			return NULL;
		}

		return shdr;
	}

	return NULL;
}

static struct resource_table *
find_resource_table(unsigned int addr, int *tablesz)
{
	Elf32_Shdr *shdr;
	Elf32_Shdr sectionheader;
	struct resource_table *ptable;
	u8 *elf_data = (u8 *)addr;

	shdr = find_table(addr);
	if (!shdr) {
		printf("find_resource_table: failed to get resource section header\n");
		return NULL;
	}

	memcpy(&sectionheader, shdr, sizeof (sectionheader));
	ptable = (struct resource_table *)(elf_data + sectionheader.sh_offset);
	if (tablesz)
		*tablesz = sectionheader.sh_size;

	return ptable;
}

#endif

/* ======================================================================
 * A very simple elf loader, assumes the image is valid, returns the
 * entry point address.
 * ====================================================================== */
unsigned long load_elf_image_phdr(unsigned long addr)
{
	Elf32_Ehdr *ehdr;		/* Elf header structure pointer     */
	Elf32_Phdr *phdr;		/* Program header structure pointer */
#if defined(CONFIG_BOOTIPU1) || defined(CONFIG_LATE_ATTACH_BOOTIPU1) || \
				defined(CONFIG_LATE_ATTACH_BOOTIPU2)
	Elf32_Phdr proghdr;
	struct resource_table *ptable = NULL;
	int tablesz;
	int va;
	int pa;
#endif
	int i;

	ehdr = (Elf32_Ehdr *) addr;
	phdr = (Elf32_Phdr *) (addr + ehdr->e_phoff);

#if defined(CONFIG_BOOTIPU1) || defined(CONFIG_LATE_ATTACH_BOOTIPU1) || \
				defined(CONFIG_LATE_ATTACH_BOOTIPU2)
# ifdef CONFIG_IPU_RESOURCE_TABLE_MAPPING
	ptable = find_resource_table(IPU_LOAD_ADDR, &tablesz);
	if (!ptable) {
		printf("spl_boot_ipu: failed to find resource table\n");
	}
	else {
		printf("spl_boot_ipu: found resource table\n");

		table = kzalloc(tablesz, GFP_KERNEL);
		if (!table) {
			printf("resource table alloc failed!\n");
			return 1;
		}

		memcpy(table, ptable, tablesz);

		INIT_LIST_HEAD(&mappings);

		handle_resources(tablesz, loading_handlers);
	}
# endif
#endif

	/* Load each program header */
	for (i = 0; i < ehdr->e_phnum; ++i) {
#if defined(CONFIG_BOOTIPU1) || defined(CONFIG_LATE_ATTACH_BOOTIPU1) || \
				defined(CONFIG_LATE_ATTACH_BOOTIPU2)
		memcpy(&proghdr, phdr, sizeof(Elf32_Phdr));
		if (!ptable) {
			if (proghdr.p_paddr < 0x4000) {
				/* L2_BOOT mapping of IPU1: Cortex M4 - VA 0x0 = PA 0x58820000 */
				proghdr.p_paddr += 0x58820000;
			} else if (proghdr.p_paddr >= 0x00300000 && proghdr.p_paddr < 0x00320000) {
				/* OCMC mapping of Cortex M4 - VA 0x00300000 = PA 0x40300000 */
				proghdr.p_paddr += 0x40000000;
			} else if (proghdr.p_paddr >= 0x20004000 &&  proghdr.p_paddr < 0x20040000) {
				/* L2_RAM mapping of IPU1: Cortex M4 - VA 0x20004000 = PA 0x58824000 */
				proghdr.p_paddr += 0x38820000; /* section.addr - 0x20000000 + 0x58820000; */
			}
		} else {
			va = proghdr.p_paddr;
			pa = va_to_pa(va);
			if (pa)
				proghdr.p_paddr = pa;
		}

		void *dst = (void *)(uintptr_t) proghdr.p_paddr;
		void *src = (void *) addr + proghdr.p_offset;
		debug("Loading phdr %i to 0x%p (%i bytes)\n",
			i, dst, proghdr.p_filesz);
		if (proghdr.p_filesz)
			memcpy(dst, src, proghdr.p_filesz);
		if (!ptable) {
			if ((proghdr.p_filesz != proghdr.p_memsz) && (proghdr.p_paddr-0x58820000) > 0x4000 && proghdr.p_memsz>9 )
				memset(dst + proghdr.p_filesz, 0x00,
					   proghdr.p_memsz - proghdr.p_filesz);
		} else {
			if (proghdr.p_filesz != proghdr.p_memsz)
				memset(dst + proghdr.p_filesz, 0x00,
					   proghdr.p_memsz - proghdr.p_filesz);
		}
		/*Don't have to flush cache if greater than 15MB */
		if (proghdr.p_memsz < 15*1024*1024)
			flush_cache((unsigned long)dst, proghdr.p_filesz);
#else
		void *dst = (void *)(uintptr_t) phdr->p_paddr;
		void *src = (void *) addr + phdr->p_offset;
		debug("Loading phdr %i to 0x%p (%i bytes)\n",
			i, dst, phdr->p_filesz);
		if (phdr->p_filesz)
			memcpy(dst, src, phdr->p_filesz);
		if (phdr->p_filesz != phdr->p_memsz)
			memset(dst + phdr->p_filesz, 0x00,
				phdr->p_memsz - phdr->p_filesz);
		flush_cache((unsigned long)dst, phdr->p_filesz);
#endif
		++phdr;
	}

	return ehdr->e_entry;
}

#ifndef CONFIG_SPL_BUILD
static unsigned long load_elf_image_shdr(unsigned long addr)
{
	Elf32_Ehdr *ehdr;		/* Elf header structure pointer     */
	Elf32_Shdr *shdr;		/* Section header structure pointer */
	unsigned char *strtab = 0;	/* String table pointer             */
	unsigned char *image;		/* Binary image pointer             */
	int i;				/* Loop counter                     */

	/* -------------------------------------------------- */

	ehdr = (Elf32_Ehdr *) addr;

	/* Find the section header string table for output info */
	shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
			       (ehdr->e_shstrndx * sizeof(Elf32_Shdr)));

	if (shdr->sh_type == SHT_STRTAB)
		strtab = (unsigned char *) (addr + shdr->sh_offset);

	/* Load each appropriate section */
	for (i = 0; i < ehdr->e_shnum; ++i) {
		shdr = (Elf32_Shdr *) (addr + ehdr->e_shoff +
				       (i * sizeof(Elf32_Shdr)));

		if (!(shdr->sh_flags & SHF_ALLOC)
		   || shdr->sh_addr == 0 || shdr->sh_size == 0) {
			continue;
		}

		if (strtab) {
			debug("%sing %s @ 0x%08lx (%ld bytes)\n",
				(shdr->sh_type == SHT_NOBITS) ?
					"Clear" : "Load",
				&strtab[shdr->sh_name],
				(unsigned long) shdr->sh_addr,
				(long) shdr->sh_size);
		}

		if (shdr->sh_type == SHT_NOBITS) {
			memset((void *)(uintptr_t) shdr->sh_addr, 0,
				shdr->sh_size);
		} else {
			image = (unsigned char *) addr + shdr->sh_offset;
			memcpy((void *)(uintptr_t) shdr->sh_addr,
				(const void *) image,
				shdr->sh_size);
		}
		flush_cache(shdr->sh_addr, shdr->sh_size);
	}

	return ehdr->e_entry;
}

/* ====================================================================== */
U_BOOT_CMD(
	bootelf,      3,      0,      do_bootelf,
	"Boot from an ELF image in memory",
	"[-p|-s] [address]\n"
	"\t- load ELF image at [address] via program headers (-p)\n"
	"\t  or via section headers (-s)"
);

U_BOOT_CMD(
	bootvx,      2,      0,      do_bootvx,
	"Boot vxWorks from an ELF image",
	" [address] - load address of vxWorks ELF image."
);
#endif
