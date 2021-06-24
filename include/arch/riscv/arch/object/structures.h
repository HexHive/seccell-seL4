/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#ifndef __ASSEMBLER__
#include <config.h>
#include <assert.h>
#include <util.h>
#include <api/types.h>
#include <arch/types.h>
#include <arch/object/structures_gen.h>
#include <arch/machine/hardware.h>
#include <arch/machine/registerset.h>
#include <mode/object/structures.h>

#define tcbArchCNodeEntries tcbCNodeEntries

struct asid_pool {
    pte_t *array[BIT(asidLowBits)];
};

typedef struct asid_pool asid_pool_t;

#define ASID_POOL_PTR(r)    ((asid_pool_t*)r)
#define ASID_POOL_REF(p)    ((word_t)p)
#define ASID_BITS           (asidHighBits + asidLowBits)
#define nASIDPools          BIT(asidHighBits)
#define ASID_LOW(a)         (a & MASK(asidLowBits))
#define ASID_HIGH(a)        ((a >> asidLowBits) & MASK(asidHighBits))

typedef struct arch_tcb {
    user_context_t tcbContext;
} arch_tcb_t;

enum vm_rights {
    VMKernelOnly = 1,
    VMReadOnly = 2,
    VMReadWrite = 3
};
typedef word_t vm_rights_t;

#ifdef CONFIG_RISCV_SECCELL
typedef rtcell_t vspace_root_t;
#else
typedef pte_t vspace_root_t;
#endif /* CONFIG_RISCV_SECCELL */

/* Generic fastpath.c code expects pde_t for stored_hw_asid
 * that's a workaround in the time being.
 */
typedef pte_t pde_t;

#define PTE_PTR(r) ((pte_t *)(r))
#define PTE_REF(p) ((word_t)(p))

#define PT_SIZE_BITS 12
#define PT_PTR(r) ((pte_t *)(r))
#define PT_REF(p) ((word_t)(p))

#define PTE_SIZE_BITS   seL4_PageTableEntryBits
#define PT_INDEX_BITS   seL4_PageTableIndexBits

#define RT_PPN_BITS     seL4_SecCellsPPNBits
#define RT_VPN_BITS     seL4_SecCellsVPNBits
#define RT_PTR(r)       ((rtcell_t *)(r))
#define RT_META_PTR(r)  ((rtmeta_t *)(r))

#define VR_PTR(r)       ((vspace_root_t *)(r))

#define WORD_BITS   (8 * sizeof(word_t))
#define WORD_PTR(r) ((word_t *)(r))

#ifdef CONFIG_RISCV_SECCELL
/* Helper functions to handle permissions in memory in accordance with
   the defined structure (see structures.bf) */

/* Create a permission structure from a byte-sized permission table entry */
static inline rtperm_t rtperm_from_uint8(uint8_t encoded_perms) {
    rtperm_t perms = { .words = {(word_t)encoded_perms} };
    return perms;
}

/* Create a byte-sized permission bitstring from a permission structure
   The main objective here is to hide the underlying structure, i.e., the
   words array access from more high-level code */
static inline uint8_t rtperm_to_uint8(rtperm_t perms) {
    return (uint8_t)perms.words[0];
}
#endif /* CONFIG_RISCV_SECCELL */

static inline bool_t CONST cap_get_archCapIsPhysical(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {

    case cap_frame_cap:
        return true;

    case cap_page_table_cap:
        return true;

#ifdef CONFIG_RISCV_SECCELL
    case cap_range_cap:
        return true;

    case cap_range_table_cap:
        return true;
#endif /* CONFIG_RISCV_SECCELL */

    case cap_asid_control_cap:
        return false;

    case cap_asid_pool_cap:
        return true;

    default:
        /* unreachable */
        return false;
    }
}

static inline word_t CONST cap_get_archCapSizeBits(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_frame_cap:
        return pageBitsForSize(cap_frame_cap_get_capFSize(cap));

    case cap_page_table_cap:
        return PT_SIZE_BITS;

#ifdef CONFIG_RISCV_SECCELL
    case cap_range_cap: {
        word_t bits = seL4_MinRangeBits;
        size_t range_size = cap_range_cap_get_capRSize(cap) << seL4_MinRangeBits;
        while (BIT(bits) < range_size) {
            bits++;
        }
        return bits;
    }

    /* TODO: Adapt to real range table size */
    case cap_range_table_cap:
        return PT_SIZE_BITS;
#endif /* CONFIG_RISCV_SECCELL */

    case cap_asid_control_cap:
        return 0;

    case cap_asid_pool_cap:
        return seL4_ASIDPoolBits;

    default:
        assert(!"Unknown cap type");
        /* Unreachable, but GCC can't figure that out */
        return 0;
    }
}

static inline void *CONST cap_get_archCapPtr(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {

    case cap_frame_cap:
        return (void *)(cap_frame_cap_get_capFBasePtr(cap));

    case cap_page_table_cap:
        return PT_PTR(cap_page_table_cap_get_capPTBasePtr(cap));

#ifdef CONFIG_RISCV_SECCELL
    case cap_range_cap:
        return (void *)(cap_range_cap_get_capRBasePtr(cap));

    case cap_range_table_cap:
        return RT_PTR(cap_range_table_cap_get_capRTBasePtr(cap));
#endif /* CONFIG_RISCV_SECCELL */

    case cap_asid_control_cap:
        return NULL;

    case cap_asid_pool_cap:
        return ASID_POOL_PTR(cap_asid_pool_cap_get_capASIDPool(cap));

    default:
        assert(!"Unknown cap type");
        /* Unreachable, but GCC can't figure that out */
        return NULL;
    }
}

static inline bool_t CONST Arch_isCapRevocable(cap_t derivedCap, cap_t srcCap)
{
    return false;
}

#endif /* !__ASSEMBLER__  */

