/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <autoconf.h>

typedef enum _object {
    // TODO: #ifndef CONFIG_RISCV_SECCELL as soon as no reference to pages exists anymore
    seL4_RISCV_4K_Page = seL4_ModeObjectTypeCount,
    seL4_RISCV_Mega_Page,
    seL4_RISCV_PageTableObject,
#ifdef CONFIG_RISCV_SECCELL
    seL4_RISCV_RangeObject,
    seL4_RISCV_RangeTableObject,
#endif /* CONFIG_RISCV_SECCELL */
    seL4_ObjectTypeCount
} seL4_ArchObjectType;

typedef seL4_Word object_t;
