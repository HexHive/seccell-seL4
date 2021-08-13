/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <types.h>
#include <api/failures.h>
#include <object/structures.h>

cap_t create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg);
void map_it_pt_cap(cap_t vspace_cap, cap_t pt_cap);
void map_it_frame_cap(cap_t vspace_cap, cap_t frame_cap);
#ifdef CONFIG_RISCV_SECCELL
void map_it_range_cap(cap_t vspace_cap, cap_t range_cap);
#endif /* CONFIG_RISCV_SECCELL */
void map_kernel_window(void);
void map_kernel_frame(paddr_t paddr, pptr_t vaddr, vm_rights_t vm_rights);
#ifdef CONFIG_RISCV_SECCELL
void map_kernel_range(paddr_t paddr, pptr_t vaddr, size_t size);
#endif /* CONFIG_RISCV_SECCELL */
void activate_kernel_vspace(void);
void write_it_asid_pool(cap_t it_ap_cap, cap_t it_lvl1pt_cap);


/* ==================== BOOT CODE FINISHES HERE ==================== */
#define IT_ASID 1

void idle_thread(void);
#define idleThreadStart (&idle_thread)

struct lookupPTSlot_ret {
    pte_t *ptSlot;
    word_t ptBitsLeft;
};

typedef struct lookupPTSlot_ret lookupPTSlot_ret_t;

#ifdef CONFIG_RISCV_SECCELL
typedef word_t rtIndex_t;
#endif /* CONFIG_RISCV_SECCELL */

struct findVSpaceForASID_ret {
    exception_t status;
    vspace_root_t *vspace_root;
};
typedef struct findVSpaceForASID_ret findVSpaceForASID_ret_t;

#ifdef CONFIG_RISCV_SECCELL
void copyGlobalMappings(rtcell_t *newRt);
#else
void copyGlobalMappings(pte_t *newlvl1pt);
#endif /* CONFIG_RISCV_SECCELL */
word_t *PURE lookupIPCBuffer(bool_t isReceiver, tcb_t *thread);
#ifdef CONFIG_RISCV_SECCELL
rtIndex_t lookupRTCell(rtcell_t *rt, vptr_t vptr);
#endif /* CONFIG_RISCV_SECCELL */
lookupPTSlot_ret_t lookupPTSlot(pte_t *lvl1pt, vptr_t vptr);
exception_t handleVMFault(tcb_t *thread, vm_fault_type_t vm_faultType);
void unmapPageTable(asid_t, vptr_t vaddr, pte_t *pt);
void unmapPage(vm_page_size_t page_size, asid_t asid, vptr_t vptr, pptr_t pptr);
#ifdef CONFIG_RISCV_SECCELL
void unmapRange(asid_t asid, vptr_t vptr_start, vptr_t vptr_end, pptr_t pptr, bool_t brute);
void invalidateRange(asid_t asid, vptr_t vptr, pptr_t pptr);
#endif /* CONFIG_RISCV_SECCELL */
void deleteASID(asid_t asid, vspace_root_t *vspace);
void deleteASIDPool(asid_t asid_base, asid_pool_t *pool);
bool_t CONST isValidVTableRoot(cap_t cap);
exception_t checkValidIPCBuffer(vptr_t vptr, cap_t cap);
vm_rights_t CONST maskVMRights(vm_rights_t vm_rights,
                               seL4_CapRights_t cap_rights_mask);
exception_t decodeRISCVMMUInvocation(word_t label, word_t length, cptr_t cptr,
                                     cte_t *cte, cap_t cap, word_t *buffer);
exception_t performPageTableInvocationMap(cap_t cap, cte_t *ctSlot,
                                          pte_t lvl1pt, pte_t *ptSlot);
exception_t performPageTableInvocationUnmap(cap_t cap, cte_t *ctSlot);
exception_t performPageInvocationMapPTE(cap_t cap, cte_t *ctSlot,
                                        pte_t pte, pte_t *base);
exception_t performPageInvocationUnmap(cap_t cap, cte_t *ctSlot);
void setVMRoot(tcb_t *tcb);

#ifdef CONFIG_PRINTING
void Arch_userStackTrace(tcb_t *tptr);
#endif

