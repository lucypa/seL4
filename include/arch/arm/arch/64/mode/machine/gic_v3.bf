--
-- Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
--
-- SPDX-License-Identifier: GPL-2.0-only
--

#include <config.h>
-- Default base size: uint64_t
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
base 64(48,0)

block virq_invalid {
    field virqType      2
    padding             1
    field virqGroup     1
    padding             4
    field virqPriority  8
    padding             3
    padding             3
    field virqEOIIRQEN  1
    padding             9
    field virqIRQ       32
}

block virq_active {
    field virqType      2
    padding             1
    field virqGroup     1
    padding             4
    field virqPriority  8
    padding             3
    padding             3
    field virqEOIIRQEN  1
    padding             9
    field virqIRQ       32
}

block virq_pending {
    field virqType      2
    padding             1
    field virqGroup     1
    padding             4
    field virqPriority  8
    padding             3
    padding             3
    field virqEOIIRQEN  1
    padding             9
    field virqIRQ       32
}

tagged_union virq virqType {
    tag virq_invalid    0
    tag virq_pending    1
    tag virq_active     2
}

#endif /* CONFIG_ARM_HYPERVISOR_SUPPORT */
