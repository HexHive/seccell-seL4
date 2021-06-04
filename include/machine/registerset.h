/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <util.h>
#include <arch/types.h>
#include <arch/machine/registerset.h>
#include <arch/object/structures.h>

typedef enum {
    MessageID_Syscall,
    MessageID_Exception,
#ifdef CONFIG_KERNEL_MCS
    MessageID_TimeoutReply,
#endif
} MessageID_t;

#ifdef CONFIG_KERNEL_MCS
#define MAX_MSG_SIZE MAX(n_syscallMessage, MAX(n_timeoutMessage, n_exceptionMessage))
#else
#define MAX_MSG_SIZE MAX(n_syscallMessage, n_exceptionMessage)
#endif
extern const register_t fault_messages[][MAX_MSG_SIZE] VISIBLE;

static inline void setRegister(tcb_t *thread, register_t reg, word_t w)
{
    thread->tcbArch.tcbContext.registers[reg] = w;
}

static inline word_t PURE getRegister(tcb_t *thread, register_t reg)
{
    return thread->tcbArch.tcbContext.registers[reg];
}

#ifdef CONFIG_RISCV_SECCELL
/* TODO: This is an architecture-specific function and should thus be located in
   architecture-specific files. However, due to include dependencies, this doesn't
   work. Investigate three options further: somehow work around the dependencies,
   change the function signature so that it doesn't rely on tcb_t anymore or just
   leave the function here, even though this is ugly */
static inline word_t PURE getNSecDivs(tcb_t *thread)
{
    return thread->tcbArch.tcbContext.n_secdivs;
}
#endif /* CONFIG_RISCV_SECCELL */

#ifdef CONFIG_KERNEL_MCS
word_t getNBSendRecvDest(void);
#endif

