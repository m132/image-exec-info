/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __COMMON_H
#define __COMMON_H

#define ADVANCE_BY(ptr, bytes) \
    ptr = (typeof (ptr)) ((UINT8 *) ptr + bytes)

#endif /* __COMMON_H */
