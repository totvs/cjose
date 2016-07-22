 /*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/util.h>

#include <jansson.h>
#include <openssl/crypto.h>
#include <stdlib.h>

static cjose_alloc_fn_t _alloc;
static cjose_realloc_fn_t _realloc;
static cjose_dealloc_fn_t _dealloc;

void cjose_set_alloc_funcs(cjose_alloc_fn_t alloc,
                           cjose_realloc_fn_t realloc,
                           cjose_dealloc_fn_t dealloc)
{
    // save "locally"
    _alloc = alloc;
    _realloc = realloc;
    _dealloc = dealloc;
    // set upstream
    json_set_alloc_funcs(_alloc, _dealloc);
    CRYPTO_set_mem_functions(_alloc, _realloc, _dealloc);
}

cjose_alloc_fn_t cjose_get_alloc()
{
    return (!_alloc) ?
           malloc :
           _alloc;
}

cjose_realloc_fn_t cjose_get_realloc()
{
    return (!_realloc) ?
           realloc :
           _realloc;
}

cjose_dealloc_fn_t cjose_get_dealloc()
{
    return (!_dealloc) ?
           free :
           _dealloc;
}

int cjose_const_memcmp(
        const uint8_t *a,
        const uint8_t *b,
        const size_t size)
{
    unsigned char result = 0;
    for (size_t i = 0; i < size; i++)
    {
        result |= a[i] ^ b[i];
    }
    return result;
}
