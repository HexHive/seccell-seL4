/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <benchmark/benchmark.h>
#include <api/failures.h>
#include <api/syscall.h>
#include <kernel/boot.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <object/tcb.h>
#include <machine/io.h>
#include <model/preemption.h>
#include <model/statedata.h>
#include <object/cnode.h>
#include <object/untyped.h>
#include <arch/api/invocation.h>
#include <arch/kernel/vspace.h>
#include <linker.h>
#include <arch/machine.h>
#include <plat/machine/hardware.h>
#include <kernel/stack.h>
#include <util.h>

struct resolve_ret {
    paddr_t frameBase;
    vm_page_size_t frameSize;
    bool_t valid;
};
typedef struct resolve_ret resolve_ret_t;

#ifdef CONFIG_RISCV_SECCELL
typedef struct {
    size_t N, /* number of SecCells                                       */
           M, /* number of SecDivs                                        */
           S, /* number of 64-byte cache lines for SecCells               */
           T; /* number of 64-byte cache lines for permissions per SecDiv */
} rt_parameters_t;
#endif /* CONFIG_RISCV_SECCELL */

static exception_t performPageGetAddress(void *vbase_ptr);

static word_t CONST RISCVGetWriteFromVMRights(vm_rights_t vm_rights)
{
    /* Write-only frame cap rights not currently supported. */
    return vm_rights == VMReadWrite;
}

static inline word_t CONST RISCVGetReadFromVMRights(vm_rights_t vm_rights)
{
    /* Write-only frame cap rights not currently supported.
     * Kernel-only conveys no user rights. */
    return vm_rights != VMKernelOnly;
}

static inline bool_t isPTEPageTable(pte_t *pte)
{
    return pte_ptr_get_valid(pte) &&
           !(pte_ptr_get_read(pte) || pte_ptr_get_write(pte) || pte_ptr_get_execute(pte));
}

/** Helper function meant only to be used for mapping the kernel
 * window.
 *
 * Maps all pages with full RWX and supervisor perms by default.
 */
static pte_t pte_next(word_t phys_addr, bool_t is_leaf)
{
    word_t ppn = (word_t)(phys_addr >> 12);

    uint8_t read = is_leaf ? 1 : 0;
    uint8_t write = read;
    uint8_t exec = read;

    return pte_new(ppn,
                   0,     /* sw */
                   1,     /* dirty */
                   1,     /* accessed */
                   1,     /* global */
                   0,     /* user */
                   exec,  /* execute */
                   write, /* write */
                   read,  /* read */
                   1      /* valid */
                  );
}

#ifdef CONFIG_RISCV_SECCELL
static rtcell_t rtcell_new_helper(uint64_t vpn_start, uint64_t vpn_end, uint64_t ppn)
{
    /* Get rid of bit-extensions */
    vpn_end = vpn_end & MASK(RT_VPN_BITS);
    vpn_start = vpn_start & MASK(RT_VPN_BITS);
    ppn = ppn & MASK(RT_PPN_BITS);

    /*
     * Calculate position after which vpn_end is split in the bitfield block,
     * c.f. include/arch/riscv/arch/64/mode/object/structures.bf
     * TODO: Improve calculation => currently based on inherent knowledge of
     * block size (blocks built of uint64_t words)
     */
    size_t split = (sizeof(uint64_t) * 8) - RT_VPN_BITS;
    /* New cells are not marked as deleted but marked as valid by default */
    return rtcell_new(1, ppn, vpn_end >> split, vpn_end & ((1ull << split) - 1), vpn_start);
}

static word_t rtcell_get_vpn_end_helper(rtcell_t cell)
{
    word_t vpn_end;
    /*
     * Calculate position after which vpn_end is split in the bitfield block,
     * c.f. include/arch/riscv/arch/64/mode/object/structures.bf
     * TODO: Improve calculation => currently based on inherent knowledge of
     * block size (blocks built of uint64_t words)
     */
    size_t split = (sizeof(uint64_t) * 8) - RT_VPN_BITS;

    vpn_end = rtcell_get_vpn_end_top(cell);
    vpn_end <<= split;
    vpn_end |= rtcell_get_vpn_end(cell);

    return vpn_end;
}

static rt_parameters_t get_rt_parameters(rtcell_t *range_table)
{
    rt_parameters_t params = {
        .N = rtmeta_ptr_get_N(RT_META_PTR(range_table)),
        .M = rtmeta_ptr_get_M(RT_META_PTR(range_table)),
        .S = rtmeta_ptr_get_T(RT_META_PTR(range_table)) * 16,
        .T = rtmeta_ptr_get_T(RT_META_PTR(range_table))
    };

    return params;
}

static void rt_resize_inc(rtcell_t *rt)
{
    rt_parameters_t old_params = get_rt_parameters(rt);
    size_t new_T = ROUND_UP(old_params.N + 1, 6) / 64;
    rt_parameters_t new_params = {
        .S = new_T * 16,
        .T = new_T
    };

    /* Only resize if it is even necessary */
    if (old_params.T != new_params.T) {
        /* Assert no overlapping between old and new permissions => code works anyways, but in the case of overlapping,
           the resizing is not atomic (i.e., there are two exact same copies of the permissions and resizing happens by
           only updating T => during and after resizing, permissions are valid from both kernel's and hardware's POV) */
        /* TODO: increase T by so much that we prevent overlapping altogether, i.e, new cell location covers also whole
           old permission location? */
        assert((uint8_t *)(rt) + (64 * new_params.S) >=
            (uint8_t *)(rt) + (64 * old_params.S) + (64 * old_params.T * old_params.M));

        for (unsigned int i = 0; i < old_params.M; i++) {
            /* Start from the end to not overwrite other data */
            unsigned int secdiv_id = old_params.M - i - 1;

            uint8_t *old_perms = (uint8_t *)(rt) + (64 * old_params.S) + (64 * old_params.T * secdiv_id);
            uint8_t *new_perms = (uint8_t *)(rt) + (64 * new_params.S) + (64 * new_params.T * secdiv_id);

            /* Copy permissions to new location */
            /* Note: permissions are stored as uint8_t, copy size thus doesn't have to be scaled.
               Also, use old cell count since adding cells and perms happens only after resizing */
            memcpy(new_perms, old_perms, old_params.N);
        }
        /* Update metacell value for T */
        rtmeta_ptr_set_T(RT_META_PTR(rt), new_params.T);

        /* Clear (now unused) region used by old permissions */
        memset(((uint8_t *)rt) + (64 * old_params.S), 0, 64 * (new_params.S - old_params.S));
    }
}

static void rt_delete_cell(rtcell_t *range_table, unsigned int index)
{
    rt_parameters_t params = get_rt_parameters(range_table);
    uint8_t *perms = (uint8_t *)(range_table) + (64 * params.S);

    /* Phase 1: remove cell and permissions */
    /* Amount of memory to shift back to overwrite the cell to delete */
    size_t length = (params.N - (index + 1)) * sizeof(rtcell_t);
    /* Overwrite the deleted cell by shifting subsequent cells */
    memcpy((void *)(range_table + index), (void *)(range_table + index + 1), length);
    memset((void *)(range_table + params.N - 1), 0, sizeof(rtcell_t));

    /* Amount of memory to shift back to overwrite the permissions to delete */
    length = (params.N - (index + 1));
    for (secdivid_t secdiv = 0; secdiv < params.M; secdiv++) {
        uint8_t *secdiv_perms = perms + (64 * params.T * secdiv);
        /* Overwrite permissions for deleted cell by shifting subsequent permissions */
        memcpy((void *)(secdiv_perms + index), (void *)(secdiv_perms + index + 1), length);
        secdiv_perms[params.N - 1] = 0;
    }

    /* Deleted cell and permissions => update cell count */
    params.N--;
    rtmeta_ptr_set_N(RT_META_PTR(range_table), params.N);

    /* Phase 2: resize range table */
    size_t new_T = ROUND_UP(params.N, 6) / 64;
    rt_parameters_t new_params = {
        .S = new_T * 16,
        .T = new_T
    };
    /* Only resize if it is even necessary */
    if (new_params.T != params.T) {
        for (secdivid_t secdiv = 0; secdiv < params.M; secdiv++) {
            uint8_t *new_perms = (uint8_t *)(range_table) + (64 * new_params.S) + (64 * new_params.T * secdiv);
            uint8_t *old_perms = (uint8_t *)(range_table) + (64 * params.S) + (64 * params.T * secdiv);

            /* Copy permissions to new location */
            /* Note: permissions are stored as uint8_t, copy size thus doesn't have to be scaled
               Also, use new cell count since deleting cells and perms happens before resizing */
            memcpy(new_perms, old_perms, params.N);
            /* Clear (now unused) region used by old permissions */
            memset(old_perms, 0, params.N);
        }
        /* Update metacell value for T */
        rtmeta_ptr_set_T(RT_META_PTR(range_table), new_params.T);
    }
}

static word_t rt_insert_cell(rtcell_t *rt, rtcell_t cell, rt_parameters_t *params)
{
    size_t start_idx, end_idx;

    start_idx = 1;
    end_idx = params->N - 1;

    /* Binary search for insertion position index based on start virtual page number */
    while (start_idx < end_idx) {
        /* Due to rounding towards zero, start_idx <= middle_idx < end_idx
           The below assignments thus guarantee progress and eventually loop termination */
        size_t middle_idx = start_idx + ((end_idx - start_idx) / 2);

        if (rtcell_get_vpn_start(cell) > rtcell_get_vpn_start(rt[middle_idx])) {
            /* +1 because start address is higher => want to insert after current cell */
            start_idx = middle_idx + 1;
        } else {
            /* Start address is lower => want to insert before or at position of current cell */
            end_idx = middle_idx;
        }
    }

    /* Move the following cells forward by one (range table resizing not required since a call to rt_resize_inc is
       already issued before any new cell creation) */
    for (size_t idx = (params->N - 1); idx > start_idx; idx--) {
        rt[idx] = rt[idx - 1];
    }

    /* Move the permissions forward by one */
    for (secdivid_t secdiv = 0; secdiv < params->M; secdiv++) {
        uint8_t *perms = (uint8_t *)(rt) + (64 * params->S) + (64 * params->T * secdiv);
        for (size_t idx = (params->N - 1); idx > start_idx; idx--) {
            perms[idx] = perms[idx - 1];
        }
        /* Blank permissions at location for new cell */
        perms[start_idx] = 0;
    }

    /* Insert new cell */
    rt[start_idx] = cell;

    return start_idx;
}

static bool_t rtcell_is_mapped(rtcell_t *range_table, word_t vaddr)
{
    rtIndex_t cell_index = lookupRTCell(range_table, vaddr);
    return (cell_index != 0);
}
#endif /* CONFIG_RISCV_SECCELL */

/* ==================== BOOT CODE STARTS HERE ==================== */

BOOT_CODE void map_kernel_frame(paddr_t paddr, pptr_t vaddr, vm_rights_t vm_rights)
{
#if __riscv_xlen == 32
    paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(0));
    assert((paddr % RISCV_GET_LVL_PGSIZE(0)) == 0);
    kernel_root_pageTable[RISCV_GET_PT_INDEX(vaddr, 0)] = pte_next(paddr, true);
#else
    if (vaddr >= KDEV_BASE) {
        /* Map devices in 2nd-level page table */
        paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(1));
        assert((paddr % RISCV_GET_LVL_PGSIZE(1)) == 0);
        kernel_image_level2_dev_pt[RISCV_GET_PT_INDEX(vaddr, 1)] = pte_next(paddr, true);
    } else {
        paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(0));
        assert((paddr % RISCV_GET_LVL_PGSIZE(0)) == 0);
        kernel_root_pageTable[RISCV_GET_PT_INDEX(vaddr, 0)] = pte_next(paddr, true);
    }
#endif
}

#ifdef CONFIG_RISCV_SECCELL
BOOT_CODE void map_kernel_range(paddr_t paddr, pptr_t vaddr, size_t size)
{
    /* Resize range table if required */
    rt_resize_inc(kernel_root_rangeTable);

    rt_parameters_t params = get_rt_parameters(kernel_root_rangeTable);
    uint8_t *perms = ((uint8_t *)kernel_root_rangeTable) + (params.S * 64);
    /* TODO: get rid of hardcoded 21 => currently only alignment on 2MiB by rounding */
    paddr = ROUND_DOWN(paddr, 21);
    assert((paddr % BIT(21)) == 0);

    params.N++;
    /* Map the range in the permission / range table */
    rtcell_t cell = rtcell_new_helper(vaddr >> seL4_PageBits,
                                      (vaddr + size - 1) >> seL4_PageBits,
                                      paddr >> seL4_PageBits);
    word_t index = rt_insert_cell(kernel_root_rangeTable, cell, &params);
    perms[index] = rtperm_to_uint8(rtperm_new(1, 1, 0, 1, 1, 1, 1));

    /* Update cell number in metacell */
    rtmeta_ptr_set_N(RT_META_PTR(kernel_root_rangeTable), params.N);
}
#endif /* CONFIG_RISCV_SECCELL */

BOOT_CODE VISIBLE void map_kernel_window(void)
{
#ifdef CONFIG_RISCV_SECCELL
    /* Two cells for now: one for the kernel ELF image, one for the remaining physical memory */
    rt_parameters_t params = get_rt_parameters(kernel_root_rangeTable);
    uint8_t *perms = ((uint8_t *)kernel_root_rangeTable) + (params.S * 64);

    params.N++;
    /* Recall:                                                   */
    /* KERNEL_ELF_BASE = first kernel ELF virtual address        */
    /* KDEV_BASE = first device virtual address                  */
    /* KERNEL_ELF_PADDR_BASE = first kernel ELF physical address */
    rtcell_t cell = rtcell_new_helper(KERNEL_ELF_BASE >> seL4_PageBits,
                                      (KDEV_BASE - 1) >> seL4_PageBits,
                                      KERNEL_ELF_PADDR_BASE >> seL4_PageBits);
    word_t index = rt_insert_cell(kernel_root_rangeTable, cell, &params);
    perms[index] = rtperm_to_uint8(rtperm_new(1, /* dirty    */
                                              1, /* accessed */
                                              0, /* global   */
                                              1, /* exec     */
                                              1, /* write    */
                                              1, /* read     */
                                              1  /* valid    */));

    /* Recall:                                                               */
    /* PPTR_BASE = first virtual address of kernels physical memory window   */
    /* PPTR_TOP = first virtual address after kernels physical memory window */
    /* PADDR_BASE = first physical address of kernels physical memory window */
    params.N++;
    cell = rtcell_new_helper(PPTR_BASE >> seL4_PageBits,
                             (PPTR_TOP - 1) >> seL4_PageBits,
                             PADDR_BASE >> seL4_PageBits);
    index = rt_insert_cell(kernel_root_rangeTable, cell, &params);
    perms[index] = rtperm_to_uint8(rtperm_new(1, 1, 0, 1, 1, 1, 1));

    /* Update cell number in metacell */
    rtmeta_ptr_set_N(RT_META_PTR(kernel_root_rangeTable), params.N);

    /* Map kernel devices into their region: KDEV_BASE to 2^64 - 1 */
    map_kernel_devices();
#else
    /* mapping of KERNEL_ELF_BASE (virtual address) to kernel's
     * KERNEL_ELF_PHYS_BASE  */
    assert(CONFIG_PT_LEVELS > 1 && CONFIG_PT_LEVELS <= 4);

    /* kernel window starts at PPTR_BASE */
    word_t pptr = PPTR_BASE;

    /* first we map in memory from PADDR_BASE */
    word_t paddr = PADDR_BASE;
    while (pptr < PPTR_TOP) {
        assert(IS_ALIGNED(pptr, RISCV_GET_LVL_PGSIZE_BITS(0)));
        assert(IS_ALIGNED(paddr, RISCV_GET_LVL_PGSIZE_BITS(0)));

        kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);

        pptr += RISCV_GET_LVL_PGSIZE(0);
        paddr += RISCV_GET_LVL_PGSIZE(0);
    }
    /* now we should be mapping the 1GiB kernel base */
    assert(pptr == PPTR_TOP);
    pptr = ROUND_DOWN(KERNEL_ELF_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    paddr = ROUND_DOWN(KERNEL_ELF_PADDR_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));

#if __riscv_xlen == 32
    kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);
    pptr += RISCV_GET_LVL_PGSIZE(0);
    paddr += RISCV_GET_LVL_PGSIZE(0);
#ifdef CONFIG_KERNEL_LOG_BUFFER
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KS_LOG_PPTR, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_log_buffer_pt), false);
#endif
#else
    word_t index = 0;
    /* The kernel image are mapped twice, locating the two indexes in the
     * root page table, pointing them to the same second level page table.
     */
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    while (pptr < PPTR_TOP + RISCV_GET_LVL_PGSIZE(0)) {
        kernel_image_level2_pt[index] = pte_next(paddr, true);
        index++;
        pptr += RISCV_GET_LVL_PGSIZE(1);
        paddr += RISCV_GET_LVL_PGSIZE(1);
    }

    /* Map kernel device page table */
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KDEV_BASE, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_dev_pt), false);
#endif

    /* There should be 1GiB free where we put device mapping */
    assert(pptr == UINTPTR_MAX - RISCV_GET_LVL_PGSIZE(0) + 1);
    map_kernel_devices();
#endif /* CONFIG_RISCV_SECCELL */
}

BOOT_CODE void map_it_pt_cap(cap_t vspace_cap, cap_t pt_cap)
{
    lookupPTSlot_ret_t pt_ret;
    pte_t *targetSlot;
    vptr_t vptr = cap_page_table_cap_get_capPTMappedAddress(pt_cap);
    pte_t *lvl1pt = PTE_PTR(pptr_of_cap(vspace_cap));

    /* pt to be mapped */
    pte_t *pt   = PTE_PTR(pptr_of_cap(pt_cap));

    /* Get PT slot to install the address in */
    pt_ret = lookupPTSlot(lvl1pt, vptr);

    targetSlot = pt_ret.ptSlot;

    *targetSlot = pte_new(
                      (addrFromPPtr(pt) >> seL4_PageBits),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0,  /* global */
                      0,  /* user */
                      0,  /* execute */
                      0,  /* write */
                      0,  /* read */
                      1 /* valid */
                  );
    sfence();
}

BOOT_CODE void map_it_frame_cap(cap_t vspace_cap, cap_t frame_cap)
{
#ifdef CONFIG_RISCV_SECCELL
    rtcell_t *rt = RT_PTR(pptr_of_cap(vspace_cap));
    pptr_t frame_pptr = pptr_of_cap(frame_cap);
    vptr_t frame_vptr = cap_frame_cap_get_capFMappedAddress(frame_cap);

    /* Resize range table if required */
    rt_resize_inc(rt);

    rt_parameters_t params = get_rt_parameters(rt);

    /* Add cell */
    params.N++;
    rtcell_t cell = rtcell_new_helper(frame_vptr >> seL4_PageBits,
                                      frame_vptr >> seL4_PageBits,
                                      pptr_to_paddr((void *)frame_pptr) >> seL4_PageBits);
    word_t index = rt_insert_cell(rt, cell, &params);

    uint8_t *kern_perms = (uint8_t *)(rt) + (64 * params.S);
    uint8_t *secdiv_perms = kern_perms + (64 * params.T * IT_ASID);
    /* Both kernel (supervisor) and user ASID get same permissions since
       mstatus.SUM = 0 in the standard port
       User ASID is also SecDiv ID here for the root thread */
    kern_perms[index] = secdiv_perms[index] = rtperm_to_uint8(rtperm_new(1, 1, 0, 1, 1, 1, 1));

    /* Update cell number in metacell */
    rtmeta_ptr_set_N(RT_META_PTR(rt), params.N);
#else
    pte_t *lvl1pt   = PTE_PTR(pptr_of_cap(vspace_cap));
    pte_t *frame_pptr   = PTE_PTR(pptr_of_cap(frame_cap));
    vptr_t frame_vptr = cap_frame_cap_get_capFMappedAddress(frame_cap);

    /* We deal with a frame as 4KiB */
    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, frame_vptr);
    assert(lu_ret.ptBitsLeft == seL4_PageBits);

    pte_t *targetSlot = lu_ret.ptSlot;

    *targetSlot = pte_new(
                      (pptr_to_paddr(frame_pptr) >> seL4_PageBits),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0,  /* global */
                      1,  /* user */
                      1,  /* execute */
                      1,  /* write */
                      1,  /* read */
                      1   /* valid */
                  );
#endif /* CONFIG_RISCV_SECCELL */
    sfence();
}

#ifdef CONFIG_RISCV_SECCELL
BOOT_CODE void map_it_range_cap(cap_t vspace_cap, cap_t range_cap) {
    rtcell_t *rt = RT_PTR(pptr_of_cap(vspace_cap));
    pptr_t frame_pptr = pptr_of_cap(range_cap);
    vptr_t frame_vptr = cap_range_cap_get_capRMappedAddress(range_cap);
    word_t size = cap_range_cap_get_capRSize(range_cap) << seL4_MinRangeBits;

    /* Resize range table if required */
    rt_resize_inc(rt);

    rt_parameters_t params = get_rt_parameters(rt);

    params.N++;
    /* Add cell */
    rtcell_t cell = rtcell_new_helper(frame_vptr >> seL4_PageBits,
                                      ((frame_vptr + size - 1) >> seL4_PageBits),
                                      pptr_to_paddr((void *)frame_pptr) >> seL4_PageBits);
    word_t index = rt_insert_cell(rt, cell, &params);

    /* Add permissions for newly created cell */
    uint8_t *kern_perms = (uint8_t *)(rt) + (64 * params.S);
    uint8_t *secdiv_perms = kern_perms + (64 * params.T * IT_ASID);
    /* Both kernel (supervisor) and user ASID get same permissions
       User ASID is also SecDiv ID here for the root thread */
    kern_perms[index] = secdiv_perms[index] = rtperm_to_uint8(rtperm_new(1, 1, 0, 1, 1, 1, 1));

    /* Update cell number in metacell */
    rtmeta_ptr_set_N(RT_META_PTR(rt), params.N);
}
#endif /* CONFIG_RISCV_SECCELL */

BOOT_CODE cap_t create_unmapped_it_frame_cap(pptr_t pptr, bool_t use_large)
{
    cap_t cap = cap_frame_cap_new(
                    asidInvalid,                     /* capFMappedASID       */
                    pptr,                            /* capFBasePtr          */
                    0,                               /* capFSize             */
                    0,                               /* capFVMRights         */
                    0,
                    0                                /* capFMappedAddress    */
                );

    return cap;
}

#ifndef CONFIG_RISCV_SECCELL
/* Create a page table for the initial thread */
static BOOT_CODE cap_t create_it_pt_cap(cap_t vspace_cap, pptr_t pptr, vptr_t vptr, asid_t asid)
{
    cap_t cap;
    cap = cap_page_table_cap_new(
              asid,   /* capPTMappedASID      */
              pptr,   /* capPTBasePtr         */
              1,      /* capPTIsMapped        */
              vptr    /* capPTMappedAddress   */
          );

    map_it_pt_cap(vspace_cap, cap);
    return cap;
}
#endif

BOOT_CODE word_t arch_get_n_paging(v_region_t it_v_reg)
{
    word_t n = 0;
    for (int i = 0; i < CONFIG_PT_LEVELS - 1; i++) {
        n += get_n_paging(it_v_reg, RISCV_GET_LVL_PGSIZE_BITS(i));
    }
    return n;
}

/* Create an address space for the initial thread.
 * This includes page directory and page tables */
BOOT_CODE cap_t create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg)
{
#ifdef CONFIG_RISCV_SECCELL
    /* Only create the mappings for kernel memory now, and add a cap for the
     * range table. The rest will be setup when frames are allocated */
    cap_t rt_cap;
    rt_cap = cap_range_table_cap_new(
            IT_ASID,                    /* capRTMappedASID    */
            (word_t) rootserver.vspace, /* capRTBasePtr       */
            1,                          /* capRTIsMapped      */
            (word_t) rootserver.vspace  /* capRTMappedAddress */
        );

    copyGlobalMappings(RT_PTR(rootserver.vspace));

    rt_parameters_t params = get_rt_parameters(RT_PTR(rootserver.vspace));

    /* Create and set IT permissions (no access to previous kernel mappings) */
    rtmeta_ptr_set_M(RT_META_PTR(rootserver.vspace), 2);
    uint8_t *it_perms = (uint8_t *)(rootserver.vspace + (64 * params.S) + (64 * params.T * IT_ASID));
    memset(it_perms, 0, params.N);

    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace), rt_cap);
    ndks_boot.bi_frame->userImagePaging = (seL4_SlotRegion) {
        ndks_boot.slot_pos_cur, ndks_boot.slot_pos_cur
    };

    return rt_cap;
#else
    cap_t      lvl1pt_cap;
    vptr_t     pt_vptr;

    copyGlobalMappings(PTE_PTR(rootserver.vspace));

    lvl1pt_cap =
        cap_page_table_cap_new(
            IT_ASID,               /* capPTMappedASID    */
            (word_t) rootserver.vspace,  /* capPTBasePtr       */
            1,                     /* capPTIsMapped      */
            (word_t) rootserver.vspace   /* capPTMappedAddress */
        );

    seL4_SlotPos slot_pos_before = ndks_boot.slot_pos_cur;
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace), lvl1pt_cap);

    /* create all n level PT caps necessary to cover userland image in 4KiB pages */
    for (int i = 0; i < CONFIG_PT_LEVELS - 1; i++) {

        for (pt_vptr = ROUND_DOWN(it_v_reg.start, RISCV_GET_LVL_PGSIZE_BITS(i));
             pt_vptr < it_v_reg.end;
             pt_vptr += RISCV_GET_LVL_PGSIZE(i)) {
            if (!provide_cap(root_cnode_cap,
                             create_it_pt_cap(lvl1pt_cap, it_alloc_paging(), pt_vptr, IT_ASID))
               ) {
                return cap_null_cap_new();
            }
        }

    }

    seL4_SlotPos slot_pos_after = ndks_boot.slot_pos_cur;
    ndks_boot.bi_frame->userImagePaging = (seL4_SlotRegion) {
        slot_pos_before, slot_pos_after
    };

    return lvl1pt_cap;
#endif /* CONFIG_RISCV_SECCELL */
}

BOOT_CODE void activate_kernel_vspace(void)
{
#ifdef CONFIG_RISCV_SECCELL
    setVSpaceRoot(kpptr_to_paddr(&kernel_root_rangeTable), 0);
#else
    setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
#endif /* CONFIG_RISCV_SECCELL */
}

BOOT_CODE void write_it_asid_pool(cap_t it_ap_cap, cap_t it_lvl1pt_cap)
{
    asid_pool_t *ap = ASID_POOL_PTR(pptr_of_cap(it_ap_cap));
    ap->array[IT_ASID] = VR_PTR(pptr_of_cap(it_lvl1pt_cap));
    riscvKSASIDTable[IT_ASID >> asidLowBits] = ap;
}

/* ==================== BOOT CODE FINISHES HERE ==================== */

static findVSpaceForASID_ret_t findVSpaceForASID(asid_t asid)
{
    findVSpaceForASID_ret_t ret;
    asid_pool_t *poolPtr;
    vspace_root_t *vspace_root;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (!poolPtr) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = NULL;
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    vspace_root = VR_PTR(poolPtr->array[asid & MASK(asidLowBits)]);
    if (!vspace_root) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = NULL;
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    ret.vspace_root = vspace_root;
    ret.status = EXCEPTION_NONE;
    return ret;
}

#ifdef CONFIG_RISCV_SECCELL
void copyGlobalMappings(rtcell_t *newRt)
{
    /* TODO: calculate amount of memory to copy based on range table parameters
     * For now, assume it fits into one page */
    memcpy(newRt, kernel_root_rangeTable, BIT(seL4_PageBits));
}
#else
void copyGlobalMappings(pte_t *newLvl1pt)
{
    unsigned long i;
    pte_t *global_kernel_vspace = kernel_root_pageTable;

    for (i = RISCV_GET_PT_INDEX(PPTR_BASE, 0); i < BIT(PT_INDEX_BITS); i++) {
        newLvl1pt[i] = global_kernel_vspace[i];
    }
}
#endif /* CONFIG_RISCV_SECCELL */

word_t *PURE lookupIPCBuffer(bool_t isReceiver, tcb_t *thread)
{
    word_t w_bufferPtr;
    cap_t bufferCap;
    vm_rights_t vm_rights;

    w_bufferPtr = thread->tcbIPCBuffer;
    bufferCap = TCB_PTR_CTE_PTR(thread, tcbBuffer)->cap;

    if (unlikely(cap_get_capType(bufferCap) != cap_frame_cap)) {
        return NULL;
    }
    if (unlikely(cap_frame_cap_get_capFIsDevice(bufferCap))) {
        return NULL;
    }

    vm_rights = cap_frame_cap_get_capFVMRights(bufferCap);
    if (likely(vm_rights == VMReadWrite ||
               (!isReceiver && vm_rights == VMReadOnly))) {
        word_t basePtr, pageBits;

        basePtr = cap_frame_cap_get_capFBasePtr(bufferCap);
        pageBits = pageBitsForSize(cap_frame_cap_get_capFSize(bufferCap));
        return (word_t *)(basePtr + (w_bufferPtr & MASK(pageBits)));
    } else {
        return NULL;
    }
}

static inline pte_t *getPPtrFromHWPTE(pte_t *pte)
{
    return PTE_PTR(ptrFromPAddr(pte_ptr_get_ppn(pte) << seL4_PageTableBits));
}

lookupPTSlot_ret_t lookupPTSlot(pte_t *lvl1pt, vptr_t vptr)
{
    lookupPTSlot_ret_t ret;

    word_t level = CONFIG_PT_LEVELS - 1;
    pte_t *pt = lvl1pt;

    /* this is how many bits we potentially have left to decode. Initially we have the
     * full address space to decode, and every time we walk this will be reduced. The
     * final value of this after the walk is the size of the frame that can be inserted,
     * or already exists, in ret.ptSlot. The following formulation is an invariant of
     * the loop: */
    ret.ptBitsLeft = PT_INDEX_BITS * level + seL4_PageBits;
    ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));

    while (isPTEPageTable(ret.ptSlot) && likely(0 < level)) {
        level--;
        ret.ptBitsLeft -= PT_INDEX_BITS;
        pt = getPPtrFromHWPTE(ret.ptSlot);
        ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));
    }

    return ret;
}

#ifdef CONFIG_RISCV_SECCELL
static inline rtcell_t *getPPtrFromHWRTCell(rtcell_t *cell)
{
    /* TODO: shift by PageTableBits here because we have the same offset in both cases - maybe define own constant? */
    return RT_PTR(ptrFromPAddr(rtcell_ptr_get_ppn(cell) << seL4_PageTableBits));
}

rtIndex_t lookupRTCell(rtcell_t *rt, vptr_t vptr)
{
    /* Initialize with 0 as a kind of "error marker" => signifies that no cell containing the given
       address could be found in the address space */
    rtIndex_t ret = 0;

    /* Bring vptr into correct format for comparisons */
    vptr = (vptr >> seL4_MinRangeBits) & MASK(seL4_SecCellsVPNBits);

    rt_parameters_t params = get_rt_parameters(rt);

    rtIndex_t start_idx, end_idx;
    start_idx = 1;
    end_idx = params.N;

    /* Binary search for given vaddr */
    while (start_idx < end_idx) {
        /* Due to rounding towards zero, start_idx <= middle_idx < end_idx
           The below assignments thus guarantee progress and eventually loop termination */
        rtIndex_t middle_idx = start_idx + ((end_idx - start_idx) / 2);

        if (vptr > rtcell_get_vpn_end_helper(rt[middle_idx])) {
            /* End address is lower => want to continue search after current cell */
            start_idx = middle_idx + 1;
        } else if (vptr < rtcell_get_vpn_start(rt[middle_idx])) {
            /* Start address is higher => want to continue search before current cell */
            end_idx = middle_idx;
        } else {
            /* Found the cell => end search */
            ret = middle_idx;
            break;
        }
    }

    return ret;
}
#endif /* CONFIG_RISCV_SECCELL */

exception_t handleVMFault(tcb_t *thread, vm_fault_type_t vm_faultType)
{
    uint64_t addr;

    addr = read_stval();

    switch (vm_faultType) {
    case RISCVLoadPageFault:
    case RISCVLoadAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVLoadAccessFault, false);
        return EXCEPTION_FAULT;
    case RISCVStorePageFault:
    case RISCVStoreAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVStoreAccessFault, false);
        return EXCEPTION_FAULT;
    case RISCVInstructionPageFault:
    case RISCVInstructionAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVInstructionAccessFault, true);
        return EXCEPTION_FAULT;

    default:
        fail("Invalid VM fault type");
    }
}

void deleteASIDPool(asid_t asid_base, asid_pool_t *pool)
{
    /* Haskell error: "ASID pool's base must be aligned" */
    assert(IS_ALIGNED(asid_base, asidLowBits));

    if (riscvKSASIDTable[asid_base >> asidLowBits] == pool) {
        riscvKSASIDTable[asid_base >> asidLowBits] = NULL;
        setVMRoot(NODE_STATE(ksCurThread));
    }
}

static exception_t performASIDControlInvocation(void *frame, cte_t *slot, cte_t *parent, asid_t asid_base)
{
    /** AUXUPD: "(True, typ_region_bytes (ptr_val \<acute>frame) 12)" */
    /** GHOSTUPD: "(True, gs_clear_region (ptr_val \<acute>frame) 12)" */
    cap_untyped_cap_ptr_set_capFreeIndex(&(parent->cap),
                                         MAX_FREE_INDEX(cap_untyped_cap_get_capBlockSize(parent->cap)));

    memzero(frame, BIT(pageBitsForSize(RISCV_4K_Page)));
    /** AUXUPD: "(True, ptr_retyps 1 (Ptr (ptr_val \<acute>frame) :: asid_pool_C ptr))" */

    cteInsert(
        cap_asid_pool_cap_new(
            asid_base,          /* capASIDBase  */
            WORD_REF(frame)     /* capASIDPool  */
        ),
        parent,
        slot
    );
    /* Haskell error: "ASID pool's base must be aligned" */
    assert((asid_base & MASK(asidLowBits)) == 0);
    riscvKSASIDTable[asid_base >> asidLowBits] = (asid_pool_t *)frame;

    return EXCEPTION_NONE;
}

static exception_t performASIDPoolInvocation(asid_t asid, asid_pool_t *poolPtr, cte_t *vspaceCapSlot)
{
    cap_t cap = vspaceCapSlot->cap;
#ifdef CONFIG_RISCV_SECCELL
    rtcell_t *regionBase = RT_PTR(cap_range_table_cap_get_capRTBasePtr(cap));
    cap = cap_range_table_cap_set_capRTMappedASID(cap, asid);
    /* TODO: Figure out whether RTMappedAddress should remain in the code or not => it is set to 0 upon initialization
       here and never actually used (artifact from mirroring the page table code) */
    cap = cap_range_table_cap_set_capRTMappedAddress(cap, 0);
    cap = cap_range_table_cap_set_capRTIsMapped(cap, 1);
#else
    pte_t *regionBase = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, 0);
    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
#endif /* CONFIG_RISCV_SECCELL */
    vspaceCapSlot->cap = cap;

    copyGlobalMappings(regionBase);

    poolPtr->array[asid & MASK(asidLowBits)] = regionBase;

    return EXCEPTION_NONE;
}

void deleteASID(asid_t asid, vspace_root_t *vspace)
{
    asid_pool_t *poolPtr;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (poolPtr != NULL && poolPtr->array[asid & MASK(asidLowBits)] == vspace) {
        hwASIDFlush(asid);
        poolPtr->array[asid & MASK(asidLowBits)] = NULL;
        setVMRoot(NODE_STATE(ksCurThread));
    }
}

void unmapPageTable(asid_t asid, vptr_t vptr, pte_t *target_pt)
{
    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (unlikely(find_ret.status != EXCEPTION_NONE)) {
        /* nothing to do */
        return;
    }
    /* We won't ever unmap a top level page table */
    assert(PTE_PTR(find_ret.vspace_root) != target_pt);
    pte_t *ptSlot = NULL;
    pte_t *pt = PTE_PTR(find_ret.vspace_root);

    for (word_t i = 0; i < CONFIG_PT_LEVELS - 1 && pt != target_pt; i++) {
        ptSlot = pt + RISCV_GET_PT_INDEX(vptr, i);
        if (unlikely(!isPTEPageTable(ptSlot))) {
            /* couldn't find it */
            return;
        }
        pt = getPPtrFromHWPTE(ptSlot);
    }

    if (pt != target_pt) {
        /* didn't find it */
        return;
    }
    /* If we found a pt then ptSlot won't be null */
    assert(ptSlot != NULL);
    *ptSlot = pte_new(
                  0,  /* phy_address */
                  0,  /* sw */
                  0,  /* dirty */
                  0,  /* accessed */
                  0,  /* global */
                  0,  /* user */
                  0,  /* execute */
                  0,  /* write */
                  0,  /* read */
                  0  /* valid */
              );
    sfence();
}

static pte_t pte_pte_invalid_new(void)
{
    return (pte_t) {
        0
    };
}

void unmapPage(vm_page_size_t page_size, asid_t asid, vptr_t vptr, pptr_t pptr)
{
    findVSpaceForASID_ret_t find_ret;
    lookupPTSlot_ret_t  lu_ret;

    find_ret = findVSpaceForASID(asid);
    if (find_ret.status != EXCEPTION_NONE) {
        return;
    }

    lu_ret = lookupPTSlot(PTE_PTR(find_ret.vspace_root), vptr);
    if (unlikely(lu_ret.ptBitsLeft != pageBitsForSize(page_size))) {
        return;
    }
    if (!pte_ptr_get_valid(lu_ret.ptSlot) || isPTEPageTable(lu_ret.ptSlot)
        || (pte_ptr_get_ppn(lu_ret.ptSlot) << seL4_PageBits) != pptr_to_paddr((void *)pptr)) {
        return;
    }

    lu_ret.ptSlot[0] = pte_pte_invalid_new();
    sfence();
}

#ifdef CONFIG_RISCV_SECCELL
void unmapRange(asid_t asid, vptr_t vptr_start, vptr_t vptr_end, pptr_t pptr, bool_t brute)
{
    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (find_ret.status != EXCEPTION_NONE) {
        return;
    }
    rtcell_t *rt = RT_PTR(find_ret.vspace_root);

    rtIndex_t cell_index = lookupRTCell(rt, vptr_start);
    if (unlikely(0 == cell_index)) {
        /* Didn't find the address in the address space => should never happen */
        return;
    }

    /* Bring pointers into the correct format for following comparisons */
    vptr_start = (vptr_start >> seL4_PageBits) & MASK(seL4_SecCellsVPNBits);
    vptr_end = (vptr_end >> seL4_PageBits) & MASK(seL4_SecCellsVPNBits);
    paddr_t paddr = addrFromPPtr((void *)pptr) >> seL4_PageBits;

    rtcell_t cell = rt[cell_index];
    if (unlikely(!(vptr_start == rtcell_get_vpn_start(cell)
                   && vptr_end == rtcell_get_vpn_end_helper(cell)
                   && paddr == rtcell_get_ppn(cell)))) {
        /* There is an inconsistency between the range table contents and the capabilities - this
           should never happen! */
        return;
    }

    /* Brute unmapping means unmapping a range no matter which SecDiv might still
        have it mapped. Otherwise, unmapping only works if no SecDiv has R/W/X access
        and the valid bit set. */
    if (!brute) {
        secdivid_t secdiv_id = getRegister(NODE_STATE(ksCurThread), ReturnUID);
        rt_parameters_t params = get_rt_parameters(rt);
        uint8_t *perms = (uint8_t *)(rt) + (64 * params.S);

        /* Check whether the range is still accessible to any SecDiv other than the
        one that requested the unmapping or the kernel */
        for (secdivid_t curr_secdiv = 1; curr_secdiv < params.M; curr_secdiv++) {
            if (curr_secdiv != secdiv_id) {
                uint8_t *curr_perms_ptr = perms + (64 * params.T * curr_secdiv);
                rtperm_t curr_perms = rtperm_from_uint8(curr_perms_ptr[cell_index]);

                if (rtperm_get_valid(curr_perms)
                    && (rtperm_get_read(curr_perms)
                        || rtperm_get_write(curr_perms)
                        || rtperm_get_exec(curr_perms))) {
                    /* Cell is valid and actually accessible by another SecDiv
                       => shouldn't unmap, invalidate instead */
                    uint8_t *secdiv_perms_ptr = perms + (64 * params.T * secdiv_id);
                    rtperm_t cell_perms = rtperm_from_uint8(secdiv_perms_ptr[cell_index]);
                    cell_perms = rtperm_set_valid(cell_perms, 0);
                    secdiv_perms_ptr[cell_index] = rtperm_to_uint8(cell_perms);

                    /* Make sure the invalidation is propagated to memory */
                    sfence();
                    return;
                }
            }
        }
    }
    /* We arrive here if either brute unmapping was chosen or the range is not mapped into
        any other SecDiv => unmap the range, i.e., remove it from the range table */
    rt_delete_cell(rt, cell_index);
    /* Make sure the unmapping is propagated to memory */
    sfence();
    /* There can only be one range with those exact parameters (virtual and physical addresses), so stop iterating when we found it */
    return;
}
#endif /* CONFIG_RISCV_SECCELL */

void setVMRoot(tcb_t *tcb)
{
    cap_t threadRoot;
    asid_t asid;
#ifdef CONFIG_RISCV_SECCELL
    rtcell_t *rt;
#else
    pte_t *lvl1pt;
    findVSpaceForASID_ret_t find_ret;
#endif /* CONFIG_RISCV_SECCELL */

    threadRoot = TCB_PTR_CTE_PTR(tcb, tcbVTable)->cap;
#ifdef CONFIG_RISCV_SECCELL
    if (cap_get_capType(threadRoot) == cap_range_table_cap) {
        rt = RT_PTR(cap_range_table_cap_get_capRTBasePtr(threadRoot));

        asid = cap_range_table_cap_get_capRTMappedASID(threadRoot);

        setVSpaceRoot(addrFromPPtr(rt), asid);
    } else {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_rangeTable), 0);
    }
#else
    if (cap_get_capType(threadRoot) == cap_page_table_cap) {
        lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(threadRoot));

        asid = cap_page_table_cap_get_capPTMappedASID(threadRoot);
        find_ret = findVSpaceForASID(asid);
        if (unlikely(find_ret.status != EXCEPTION_NONE || PTE_PTR(find_ret.vspace_root) != lvl1pt)) {
            setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
            return;
        }

        setVSpaceRoot(addrFromPPtr(lvl1pt), asid);
    } else {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
    }
#endif /* CONFIG_RISCV_SECCELL */
}

bool_t CONST isValidVTableRoot(cap_t cap)
{
#ifdef CONFIG_RISCV_SECCELL
    return (cap_get_capType(cap) == cap_range_table_cap &&
            cap_range_table_cap_get_capRTIsMapped(cap));
#else
    return (cap_get_capType(cap) == cap_page_table_cap &&
            cap_page_table_cap_get_capPTIsMapped(cap));
#endif /* CONFIG_RISCV_SECCELL */
}

exception_t checkValidIPCBuffer(vptr_t vptr, cap_t cap)
{
    if (unlikely(cap_get_capType(cap) != cap_frame_cap)) {
        userError("Requested IPC Buffer is not a frame cap.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(cap_frame_cap_get_capFIsDevice(cap))) {
        userError("Specifying a device frame as an IPC buffer is not permitted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(!IS_ALIGNED(vptr, seL4_IPCBufferSizeBits))) {
        userError("Requested IPC Buffer location 0x%x is not aligned.",
                  (int)vptr);
        current_syscall_error.type = seL4_AlignmentError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    return EXCEPTION_NONE;
}

vm_rights_t CONST maskVMRights(vm_rights_t vm_rights, seL4_CapRights_t cap_rights_mask)
{
    if (vm_rights == VMReadOnly && seL4_CapRights_get_capAllowRead(cap_rights_mask)) {
        return VMReadOnly;
    }
    if (vm_rights == VMReadWrite && seL4_CapRights_get_capAllowRead(cap_rights_mask)) {
        if (!seL4_CapRights_get_capAllowWrite(cap_rights_mask)) {
            return VMReadOnly;
        } else {
            return VMReadWrite;
        }
    }
    return VMKernelOnly;
}

/* The rest of the file implements the RISCV object invocations */

static pte_t CONST makeUserPTE(paddr_t paddr, bool_t executable, vm_rights_t vm_rights)
{
    word_t write = RISCVGetWriteFromVMRights(vm_rights);
    word_t read = RISCVGetReadFromVMRights(vm_rights);
    if (unlikely(!read && !write && !executable)) {
        return pte_pte_invalid_new();
    } else {
        return pte_new(
                   paddr >> seL4_PageBits,
                   0, /* sw */
                   1, /* dirty */
                   1, /* accessed */
                   0, /* global */
                   1, /* user */
                   executable, /* execute */
                   RISCVGetWriteFromVMRights(vm_rights), /* write */
                   RISCVGetReadFromVMRights(vm_rights), /* read */
                   1 /* valid */
               );
    }
}

static inline bool_t CONST checkVPAlignment(vm_page_size_t sz, word_t w)
{
    return (w & MASK(pageBitsForSize(sz))) == 0;
}

static exception_t decodeRISCVPageTableInvocation(word_t label, word_t length,
                                                  cte_t *cte, cap_t cap, word_t *buffer)
{
    if (label == RISCVPageTableUnmap) {
        if (unlikely(!isFinalCapability(cte))) {
            userError("RISCVPageTableUnmap: cannot unmap if more than once cap exists");
            current_syscall_error.type = seL4_RevokeFirst;
            return EXCEPTION_SYSCALL_ERROR;
        }
        /* Ensure that if the page table is mapped, it is not a top level table */
        if (likely(cap_page_table_cap_get_capPTIsMapped(cap))) {
            asid_t asid = cap_page_table_cap_get_capPTMappedASID(cap);
            findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
            pte_t *pte = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
            if (unlikely(find_ret.status == EXCEPTION_NONE &&
                         PTE_PTR(find_ret.vspace_root) == pte)) {
                userError("RISCVPageTableUnmap: cannot call unmap on top level PageTable");
                current_syscall_error.type = seL4_RevokeFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageTableInvocationUnmap(cap, cte);
    }

    if (unlikely((label != RISCVPageTableMap))) {
        userError("RISCVPageTable: Illegal Operation");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(length < 2 || current_extra_caps.excaprefs[0] == NULL)) {
        userError("RISCVPageTable: truncated message");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (unlikely(cap_page_table_cap_get_capPTIsMapped(cap))) {
        userError("RISCVPageTable: PageTable is already mapped.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;
    }

    word_t vaddr = getSyscallArg(0, buffer);
    cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

    if (unlikely(cap_get_capType(lvl1ptCap) != cap_page_table_cap ||
                 cap_page_table_cap_get_capPTIsMapped(lvl1ptCap) == asidInvalid)) {
        userError("RISCVPageTableMap: Invalid top-level PageTable.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;

        return EXCEPTION_SYSCALL_ERROR;
    }

    pte_t *lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap));
    asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

    if (unlikely(vaddr >= USER_TOP)) {
        userError("RISCVPageTableMap: Virtual address cannot be in kernel window.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 0;

        return EXCEPTION_SYSCALL_ERROR;
    }

    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (unlikely(find_ret.status != EXCEPTION_NONE)) {
        userError("RISCVPageTableMap: ASID lookup failed");
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = false;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(PTE_PTR(find_ret.vspace_root) != lvl1pt)) {
        userError("RISCVPageTableMap: ASID lookup failed");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);

    /* if there is already something mapped (valid is set) or we have traversed far enough
     * that a page table is not valid to map then tell the user that they have to delete
     * something before they can put a PT here */
    if (lu_ret.ptBitsLeft == seL4_PageBits || pte_ptr_get_valid(lu_ret.ptSlot)) {
        userError("RISCVPageTableMap: All objects mapped at this address");
        current_syscall_error.type = seL4_DeleteFirst;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Get the slot to install the PT in */
    pte_t *ptSlot = lu_ret.ptSlot;

    paddr_t paddr = addrFromPPtr(
                        PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap)));
    pte_t pte = pte_new((paddr >> seL4_PageBits),
                        0, /* sw */
                        1, /* dirty */
                        1, /* accessed */
                        0,  /* global */
                        0,  /* user */
                        0,  /* execute */
                        0,  /* write */
                        0,  /* read */
                        1 /* valid */
                       );

    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, (vaddr & ~MASK(lu_ret.ptBitsLeft)));

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return performPageTableInvocationMap(cap, cte, pte, ptSlot);
}

static exception_t decodeRISCVFrameInvocation(word_t label, word_t length,
                                              cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (label) {
    case RISCVPageMap: {
        if (unlikely(length < 3 || current_extra_caps.excaprefs[0] == NULL)) {
            userError("RISCVPageMap: Truncated message.");
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        word_t vaddr = getSyscallArg(0, buffer);
        word_t w_rightsMask = getSyscallArg(1, buffer);
        vm_attributes_t attr = vmAttributesFromWord(getSyscallArg(2, buffer));
        cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

        vm_page_size_t frameSize = cap_frame_cap_get_capFSize(cap);
        vm_rights_t capVMRights = cap_frame_cap_get_capFVMRights(cap);

        if (unlikely(cap_get_capType(lvl1ptCap) != cap_page_table_cap ||
                     !cap_page_table_cap_get_capPTIsMapped(lvl1ptCap))) {
            userError("RISCVPageMap: Bad PageTable cap.");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        pte_t *lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap));
        asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

        findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
        if (unlikely(find_ret.status != EXCEPTION_NONE)) {
            userError("RISCVPageMap: No PageTable for ASID");
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (unlikely(PTE_PTR(find_ret.vspace_root) != lvl1pt)) {
            userError("RISCVPageMap: ASID lookup failed");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* check the vaddr is valid */
        word_t vtop = vaddr + BIT(pageBitsForSize(frameSize)) - 1;
        if (unlikely(vtop >= USER_TOP)) {
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (unlikely(!checkVPAlignment(frameSize, vaddr))) {
            current_syscall_error.type = seL4_AlignmentError;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Check if this page is already mapped */
        lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);
        if (unlikely(lu_ret.ptBitsLeft != pageBitsForSize(frameSize))) {
            current_lookup_fault = lookup_fault_missing_capability_new(lu_ret.ptBitsLeft);
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_t frame_asid = cap_frame_cap_get_capFMappedASID(cap);
        if (unlikely(frame_asid != asidInvalid)) {
            /* this frame is already mapped */
            if (frame_asid != asid) {
                userError("RISCVPageMap: Attempting to remap a frame that does not belong to the passed address space");
                current_syscall_error.type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return EXCEPTION_SYSCALL_ERROR;
            }
            word_t mapped_vaddr = cap_frame_cap_get_capFMappedAddress(cap);
            if (unlikely(mapped_vaddr != vaddr)) {
                userError("RISCVPageMap: attempting to map frame into multiple addresses");
                current_syscall_error.type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return EXCEPTION_SYSCALL_ERROR;
            }
            /* this check is redundant, as lookupPTSlot does not stop on a page
             * table PTE */
            if (unlikely(isPTEPageTable(lu_ret.ptSlot))) {
                userError("RISCVPageMap: no mapping to remap.");
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        } else {
            /* check this vaddr isn't already mapped */
            if (unlikely(pte_ptr_get_valid(lu_ret.ptSlot))) {
                userError("Virtual address already mapped");
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        vm_rights_t vmRights = maskVMRights(capVMRights, rightsFromWord(w_rightsMask));
        paddr_t frame_paddr = addrFromPPtr((void *) cap_frame_cap_get_capFBasePtr(cap));
        cap = cap_frame_cap_set_capFMappedASID(cap, asid);
        cap = cap_frame_cap_set_capFMappedAddress(cap,  vaddr);

        bool_t executable = !vm_attributes_get_riscvExecuteNever(attr);
        pte_t pte = makeUserPTE(frame_paddr, executable, vmRights);
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageInvocationMapPTE(cap, cte, pte, lu_ret.ptSlot);
    }

    case RISCVPageUnmap: {
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageInvocationUnmap(cap, cte);
    }

    case RISCVPageGetAddress: {

        /* Check that there are enough message registers */
        assert(n_msgRegisters >= 1);

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageGetAddress((void *)cap_frame_cap_get_capFBasePtr(cap));
    }

    default:
        userError("RISCVPage: Illegal operation.");
        current_syscall_error.type = seL4_IllegalOperation;

        return EXCEPTION_SYSCALL_ERROR;
    }

}

#ifdef CONFIG_RISCV_SECCELL
static exception_t decodeRISCVRangeTableInvocation(word_t label, word_t length, cte_t *cte,
                                                   cap_t cap, word_t *buffer)
{
    switch (label) {
        case RISCVRangeTableAddSecDiv: {
            /* Check that there are enough message registers */
            assert(n_msgRegisters >= 1);

            /* TODO: Should we reuse empty/previously deleted SecDivs? */
            rtcell_t *rt = RT_PTR(cap_range_table_cap_get_capRTBasePtr(cap));
            rt_parameters_t params = get_rt_parameters(rt);
            rtmeta_ptr_set_M(RT_META_PTR(rt), params.M + 1);
            sfence();

            /* Return SecDiv ID in the first message register */
            setRegister(NODE_STATE(ksCurThread), msgRegisters[0], params.M);
            setRegister(NODE_STATE(ksCurThread), msgInfoRegister,
                        wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, 1)));

            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
            return EXCEPTION_NONE;
        }

        case RISCVRangeTableRevokeSecDiv: {
            rtcell_t *rt = RT_PTR(cap_range_table_cap_get_capRTBasePtr(cap));
            rt_parameters_t params = get_rt_parameters(rt);

            secdivid_t secdiv = getSyscallArg(0, buffer);
            if (secdiv > (params.M - 1)) {
                /* SecDiv ID invalid / too high */
                return EXCEPTION_SYSCALL_ERROR;
            }

            /* Blank the SecDiv's permissions */
            uint8_t *secdiv_perms = (uint8_t *)rt + (64 * params.S) + (64 * params.T * secdiv);
            memset((void *)secdiv_perms, 0, params.N);

            sfence();

            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
            return EXCEPTION_NONE;
        }

        default: {
            userError("RISCVRangeTable: Illegal operation.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
    }
}

static exception_t decodeRISCVRangeInvocation(word_t label, word_t length,
                                              cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (label) {
        case RISCVRangeMap: {
            if (unlikely(length < 3 || current_extra_caps.excaprefs[0] == NULL)) {
                userError("RISCVRangeMap: Truncated message.");
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            word_t vaddr = getSyscallArg(0, buffer);
            word_t w_rightsMask = getSyscallArg(1, buffer);
            vm_attributes_t attr = vmAttributesFromWord(getSyscallArg(2, buffer));
            cap_t rtCap = current_extra_caps.excaprefs[0]->cap;
            word_t size = cap_range_cap_get_capRSize(cap) << seL4_MinRangeBits;
            vm_rights_t capVMRights = cap_range_cap_get_capRVMRights(cap);

            if (unlikely(cap_get_capType(rtCap) != cap_range_table_cap ||
                         !cap_range_table_cap_get_capRTIsMapped(rtCap))) {
                userError("RISCVRangeMap: Bad RangeTable cap.");
                current_syscall_error.type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return EXCEPTION_SYSCALL_ERROR;
            }

            rtcell_t *rt = RT_PTR(cap_range_table_cap_get_capRTBasePtr(rtCap));
            asid_t asid = cap_range_table_cap_get_capRTMappedASID(rtCap);

            findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
            if (unlikely(find_ret.status != EXCEPTION_NONE)) {
                userError("RISCVRangeMap: No RangeTable for ASID");
                current_syscall_error.type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = false;
                return EXCEPTION_SYSCALL_ERROR;
            }

            if (unlikely(find_ret.vspace_root != rt)) {
                userError("RISCVRangeMap: ASID lookup failed");
                current_syscall_error.type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return EXCEPTION_SYSCALL_ERROR;
            }

            word_t vtop = vaddr + size - 1;
            if (unlikely(vtop >= USER_TOP)) {
                userError("RISCVRangeMap: Range address too high");
                current_syscall_error.type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return EXCEPTION_SYSCALL_ERROR;
            }

            asid_t range_asid = cap_range_cap_get_capRMappedASID(cap);
            secdivid_t secdiv_id = getRegister(NODE_STATE(ksCurThread), ReturnUID);

            if (unlikely(range_asid != asidInvalid)) {
                /* Range is already mapped */
                if (range_asid != asid) {
                    userError("RISCVRangeMap: Attempting to remap a range that does not belong to the passed address space");
                    current_syscall_error.type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 1;
                    return EXCEPTION_SYSCALL_ERROR;
                }

                word_t mapped_vaddr = cap_range_cap_get_capRMappedAddress(cap);
                if (unlikely(mapped_vaddr != vaddr)) {
                    userError("RISCVRangeMap: Attempt to map range at multiple addresses");
                    current_syscall_error.type = seL4_InvalidArgument;
                    current_syscall_error.invalidArgumentNumber = 0;
                    return EXCEPTION_SYSCALL_ERROR;
                }
            } else {
                /* Make sure that this vaddr isn't already mapped */
                if (unlikely(rtcell_is_mapped(rt, vaddr))) {
                    userError("RISCVRangeMap: Virtual address already mapped");
                    current_syscall_error.type = seL4_DeleteFirst;
                    return EXCEPTION_SYSCALL_ERROR;
                }
            }

            vm_rights_t vm_rights = maskVMRights(capVMRights, rightsFromWord(w_rightsMask));
            /* TODO: Atri's prototype increments the addr by 4kiB - why? */
            paddr_t range_paddr = addrFromPPtr((void*) cap_range_cap_get_capRBasePtr(cap));

            /* Resize range table if necessary */
            rt_resize_inc(rt);

            rt_parameters_t params = get_rt_parameters(rt);
            params.N++;
            /* Add new cell */
            rtcell_t cell = rtcell_new_helper(vaddr >> seL4_PageBits,
                                              vtop >> seL4_PageBits,
                                              range_paddr >> seL4_PageBits);
            word_t index = rt_insert_cell(rt, cell, &params);

            uint8_t *perms_sup = (uint8_t *)(rt) + (64 * params.S);
            uint8_t *perms_secdiv = perms_sup + (64 * params.T * secdiv_id);
            word_t read = RISCVGetReadFromVMRights(vm_rights);
            word_t write = RISCVGetWriteFromVMRights(vm_rights);
            bool_t exec = !vm_attributes_get_riscvExecuteNever(attr);
            /* Set permissions */
            perms_sup[index] = perms_secdiv[index] = rtperm_to_uint8(rtperm_new(1, 1, 0, exec, write, read, 1));

            /* Update cell number in metacell */
            rtmeta_ptr_set_N(RT_META_PTR(rt), params.N);
            sfence();

            /* Update capability */
            cap = cap_range_cap_set_capRMappedASID(cap, asid);
            cap = cap_range_cap_set_capRMappedAddress(cap, vaddr);
            cte->cap = cap;

            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
            return EXCEPTION_NONE;
        }

        case RISCVRangeUnmap: {
            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);

            /* Unmap memory */
            if (cap_range_cap_get_capRMappedASID(cap) != asidInvalid) {
                unmapRange(cap_range_cap_get_capRMappedASID(cap),
                           cap_range_cap_get_capRMappedAddress(cap),
                           cap_range_cap_get_capRMappedAddress(cap) +
                               (cap_range_cap_get_capRSize(cap) << seL4_MinRangeBits) - 1,
                           cap_range_cap_get_capRBasePtr(cap),
                           false
                          );
            }
            /* Invalidate capability */
            cap_t slot_cap = cte->cap;
            slot_cap = cap_range_cap_set_capRMappedAddress(slot_cap, 0);
            slot_cap = cap_range_cap_set_capRMappedASID(slot_cap, asidInvalid);
            cte->cap = slot_cap;

            return EXCEPTION_NONE;
        }

        case RISCVRangeGetAddress: {
            /* Check that there are enough message registers */
            assert(n_msgRegisters >= 1);

            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);

            paddr_t capRBasePtr;
            /* Get the physical address of this range */
            capRBasePtr = addrFromPPtr((void *)cap_range_cap_get_capRBasePtr(cap));

            /* Return it in the first message register */
            setRegister(NODE_STATE(ksCurThread), msgRegisters[0], capRBasePtr);
            setRegister(NODE_STATE(ksCurThread), msgInfoRegister,
                        wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, 1)));

            return EXCEPTION_NONE;
        }

        default: {
            userError("RISCVRange: Illegal operation.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
    }
}
#endif /* CONFIG_RISCV_SECCELL */

exception_t decodeRISCVMMUInvocation(word_t label, word_t length, cptr_t cptr,
                                     cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (cap_get_capType(cap)) {

    case cap_page_table_cap:
        return decodeRISCVPageTableInvocation(label, length, cte, cap, buffer);

    case cap_frame_cap:
        return decodeRISCVFrameInvocation(label, length, cte, cap, buffer);

#ifdef CONFIG_RISCV_SECCELL
    case cap_range_table_cap:
        return decodeRISCVRangeTableInvocation(label, length, cte, cap, buffer);

    case cap_range_cap:
        return decodeRISCVRangeInvocation(label, length, cte, cap, buffer);
#endif /* CONFIG_RISCV_SECCELL */

    case cap_asid_control_cap: {
        word_t     i;
        asid_t           asid_base;
        word_t           index;
        word_t           depth;
        cap_t            untyped;
        cap_t            root;
        cte_t           *parentSlot;
        cte_t           *destSlot;
        lookupSlot_ret_t lu_ret;
        void            *frame;
        exception_t      status;

        if (label != RISCVASIDControlMakePool) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }

        if (length < 2 || current_extra_caps.excaprefs[0] == NULL
            || current_extra_caps.excaprefs[1] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        index = getSyscallArg(0, buffer);
        depth = getSyscallArg(1, buffer);
        parentSlot = current_extra_caps.excaprefs[0];
        untyped = parentSlot->cap;
        root = current_extra_caps.excaprefs[1]->cap;

        /* Find first free pool */
        for (i = 0; i < nASIDPools && riscvKSASIDTable[i]; i++);

        if (i == nASIDPools) {
            /* no unallocated pool is found */
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_base = i << asidLowBits;

        if (cap_get_capType(untyped) != cap_untyped_cap ||
            cap_untyped_cap_get_capBlockSize(untyped) != seL4_ASIDPoolBits ||
            cap_untyped_cap_get_capIsDevice(untyped)) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;

            return EXCEPTION_SYSCALL_ERROR;
        }

        status = ensureNoChildren(parentSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        frame = WORD_PTR(cap_untyped_cap_get_capPtr(untyped));

        lu_ret = lookupTargetSlot(root, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
            return lu_ret.status;
        }
        destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performASIDControlInvocation(frame, destSlot, parentSlot, asid_base);
    }

    case cap_asid_pool_cap: {
        cap_t        vspaceCap;
        cte_t       *vspaceCapSlot;
        asid_pool_t *pool;
        word_t i;
        asid_t       asid;

        if (label != RISCVASIDPoolAssign) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }
        if (current_extra_caps.excaprefs[0] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;

            return EXCEPTION_SYSCALL_ERROR;
        }

        vspaceCapSlot = current_extra_caps.excaprefs[0];
        vspaceCap = vspaceCapSlot->cap;

#ifdef CONFIG_RISCV_SECCELL
        if(unlikely(cap_get_capType(vspaceCap) != cap_range_table_cap ||
                    cap_range_table_cap_get_capRTIsMapped(vspaceCap))) {
#else
        if (unlikely(cap_get_capType(vspaceCap) != cap_page_table_cap ||
                     cap_page_table_cap_get_capPTIsMapped(vspaceCap))) {
#endif /* CONFIG_RISCV_SECCELL */
            userError("RISCVASIDPool: Invalid vspace root.");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;

            return EXCEPTION_SYSCALL_ERROR;
        }

        pool = riscvKSASIDTable[cap_asid_pool_cap_get_capASIDBase(cap) >> asidLowBits];
        if (!pool) {
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            current_lookup_fault = lookup_fault_invalid_root_new();
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (pool != ASID_POOL_PTR(cap_asid_pool_cap_get_capASIDPool(cap))) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Find first free ASID */
        asid = cap_asid_pool_cap_get_capASIDBase(cap);
        for (i = 0; i < BIT(asidLowBits) && (asid + i == 0 || pool->array[i]); i++);

        if (i == BIT(asidLowBits)) {
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid += i;

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performASIDPoolInvocation(asid, pool, vspaceCapSlot);
    }
    default:
        fail("Invalid arch cap type");
    }
}

exception_t performPageTableInvocationMap(cap_t cap, cte_t *ctSlot,
                                          pte_t pte, pte_t *ptSlot)
{
    ctSlot->cap = cap;
    *ptSlot = pte;
    sfence();

    return EXCEPTION_NONE;
}

exception_t performPageTableInvocationUnmap(cap_t cap, cte_t *ctSlot)
{
    if (cap_page_table_cap_get_capPTIsMapped(cap)) {
        pte_t *pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
        unmapPageTable(
            cap_page_table_cap_get_capPTMappedASID(cap),
            cap_page_table_cap_get_capPTMappedAddress(cap),
            pt
        );
        clearMemory((void *)pt, seL4_PageTableBits);
    }
    cap_page_table_cap_ptr_set_capPTIsMapped(&(ctSlot->cap), 0);

    return EXCEPTION_NONE;
}

static exception_t performPageGetAddress(void *vbase_ptr)
{
    paddr_t capFBasePtr;

    /* Get the physical address of this frame. */
    capFBasePtr = addrFromPPtr(vbase_ptr);

    /* return it in the first message register */
    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], capFBasePtr);
    setRegister(NODE_STATE(ksCurThread), msgInfoRegister,
                wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, 1)));

    return EXCEPTION_NONE;
}

static exception_t updatePTE(pte_t pte, pte_t *base)
{
    *base = pte;
    sfence();
    return EXCEPTION_NONE;
}

exception_t performPageInvocationMapPTE(cap_t cap, cte_t *ctSlot,
                                        pte_t pte, pte_t *base)
{
    ctSlot->cap = cap;
    return updatePTE(pte, base);
}

exception_t performPageInvocationUnmap(cap_t cap, cte_t *ctSlot)
{
    if (cap_frame_cap_get_capFMappedASID(cap) != asidInvalid) {
        unmapPage(cap_frame_cap_get_capFSize(cap),
                  cap_frame_cap_get_capFMappedASID(cap),
                  cap_frame_cap_get_capFMappedAddress(cap),
                  cap_frame_cap_get_capFBasePtr(cap)
                 );
    }

    cap_t slotCap = ctSlot->cap;
    slotCap = cap_frame_cap_set_capFMappedAddress(slotCap, 0);
    slotCap = cap_frame_cap_set_capFMappedASID(slotCap, asidInvalid);
    ctSlot->cap = slotCap;

    return EXCEPTION_NONE;
}

#ifdef CONFIG_PRINTING
void Arch_userStackTrace(tcb_t *tptr)
{
    cap_t threadRoot = TCB_PTR_CTE_PTR(tptr, tcbVTable)->cap;
    if (!isValidVTableRoot(threadRoot)) {
        printf("Invalid vspace\n");
        return;
    }

    word_t sp = getRegister(tptr, SP);
    if (!IS_ALIGNED(sp, seL4_WordSizeBits)) {
        printf("SP %p not aligned", (void *) sp);
        return;
    }

#ifdef CONFIG_RISCV_SECCELL
    /* TODO: SecDiv-based access-control even necessary? I mean, we're in kernel space here... */
    secdivid_t secdiv_id = getRegister(tptr, ReturnUID);
    rtcell_t *vspace_root = RT_PTR(pptr_of_cap(threadRoot));

    rt_parameters_t params = get_rt_parameters(vspace_root);
    uint8_t *secdiv_perms = (uint8_t *)(vspace_root) + (64 * params.S) + (64 * params.T * secdiv_id);

    for (int i = 0; i < CONFIG_USER_STACK_TRACE_LENGTH; i++) {
        word_t address = sp + (i * sizeof(word_t));
        rtIndex_t cell_index = lookupRTCell(vspace_root, address);
        if (rtperm_get_valid(rtperm_from_uint8(secdiv_perms[cell_index]))) {
            pptr_t pptr = (pptr_t)(getPPtrFromHWRTCell(vspace_root + cell_index));
            word_t *value = (word_t *)((word_t)pptr + (address & MASK(seL4_MinRangeBits)));
            printf("0x%lx: 0x%lx\n", (long) address, (long) *value);
        } else {
            printf("0x%lx: INVALID\n", (long) address);
        }
    }
#else
    pte_t *vspace_root = PTE_PTR(pptr_of_cap(threadRoot));
    for (int i = 0; i < CONFIG_USER_STACK_TRACE_LENGTH; i++) {
        word_t address = sp + (i * sizeof(word_t));
        lookupPTSlot_ret_t ret = lookupPTSlot(vspace_root, address);
        if (pte_ptr_get_valid(ret.ptSlot) && !isPTEPageTable(ret.ptSlot)) {
            pptr_t pptr = (pptr_t)(getPPtrFromHWPTE(ret.ptSlot));
            word_t *value = (word_t *)((word_t)pptr + (address & MASK(ret.ptBitsLeft)));
            printf("0x%lx: 0x%lx\n", (long) address, (long) *value);
        } else {
            printf("0x%lx: INVALID\n", (long) address);
        }
    }
#endif /* CONFIG_RISCV_SECCELL */
}
#endif /* CONFIG_PRINTING */

#ifdef CONFIG_KERNEL_LOG_BUFFER
exception_t benchmark_arch_map_logBuffer(word_t frame_cptr)
{
    lookupCapAndSlot_ret_t lu_ret;
    vm_page_size_t frameSize;
    pptr_t  frame_pptr;

    /* faulting section */
    lu_ret = lookupCapAndSlot(NODE_STATE(ksCurThread), frame_cptr);

    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        userError("Invalid cap #%lu.", frame_cptr);
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    if (cap_get_capType(lu_ret.cap) != cap_frame_cap) {
        userError("Invalid cap. Log buffer should be of a frame cap");
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    frameSize = cap_frame_cap_get_capFSize(lu_ret.cap);

    if (frameSize != RISCV_Mega_Page) {
        userError("Invalid frame size. The kernel expects large page log buffer");
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    frame_pptr = cap_frame_cap_get_capFBasePtr(lu_ret.cap);

    ksUserLogBuffer = pptr_to_paddr((void *) frame_pptr);

#if __riscv_xlen == 32
    paddr_t physical_address = ksUserLogBuffer;
    for (word_t i = 0; i < BIT(PT_INDEX_BITS); i += 1) {
        kernel_image_level2_log_buffer_pt[i] = pte_next(physical_address, true);
        physical_address += BIT(PAGE_BITS);
    }
    assert(physical_address - ksUserLogBuffer == BIT(seL4_LargePageBits));
#else
    kernel_image_level2_dev_pt[RISCV_GET_PT_INDEX(KS_LOG_PPTR, 1)] = pte_next(ksUserLogBuffer, true);
#endif

    sfence();

    return EXCEPTION_NONE;
}
#endif /* CONFIG_KERNEL_LOG_BUFFER */
