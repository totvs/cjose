/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014 Cisco Systems, Inc.  All Rights Reserved.
 */


#include <stdlib.h>
#include <json-c/json_object.h>
#include "cjose/header.h"
#include "include/header_int.h"


const char *CJOSE_HDR_ALG = "alg";
const char *CJOSE_HDR_ALG_RSA_OAEP = "RSA-OAEP";
const char *CJOSE_HDR_ALG_DIR = "dir";
const char *CJOSE_HDR_ALG_PS256 = "PS256";
const char *CJOSE_HDR_ALG_RS256 = "RS256";

const char *CJOSE_HDR_ENC = "enc";
const char *CJOSE_HDR_ENC_A256GCM = "A256GCM";

const char *CJOSE_HDR_CTY = "cty";

const char *CJOSE_HDR_KID = "kid";

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_header_new(
        cjose_err *err)
{
    cjose_header_t *retval = json_object_new_object();
    if (NULL == retval)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    return retval;
}


////////////////////////////////////////////////////////////////////////////////
void cjose_header_release(
        cjose_header_t *header)
{
    if (NULL != header)
    {
        json_object_put(header);
    }
}


////////////////////////////////////////////////////////////////////////////////
bool cjose_header_set(
        cjose_header_t *header,
        const char *attr,
        const char *value,
        cjose_err *err)
{
    if (NULL == header || NULL == attr || NULL == value)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    json_object *value_obj = json_object_new_string(value);
    if (NULL == value_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    json_object_object_add(
            header, attr, value_obj);

    return true;
}


////////////////////////////////////////////////////////////////////////////////
const char *cjose_header_get(
        cjose_header_t *header,
        const char *attr,
        cjose_err *err)
{
    if (NULL == header || NULL == attr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_object *value_obj = NULL;
    if (!json_object_object_get_ex(
            header, attr, &value_obj))
    {
        return NULL; 
    }

    return json_object_get_string(value_obj);
}
