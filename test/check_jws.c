/*!
 *
 */

#include "check_cjose.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include "include/jwk_int.h"
#include "include/jws_int.h"
#include <openssl/rand.h>

// a JWK to be re-used for unit tests
static const char *JWK_COMMON = 
    "{ \"kty\": \"RSA\", "
    "\"e\": \"AQAB\", "
    "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
    "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
    "\"d\": \"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\", "
    "\"p\": \"7X_Hk-tohqmSp8Wv1UcjLw-_DyzYZTmHuXblxWJUk54shbujVU6MQg0_6NIGi0-9Y5_yjiUQMM4wRqrMevYxqMnSzDherN1fI-nWv-PNDrxEFObIFEYJy1vHQe1fqgraoLkgVwyzvrDXtUN_EnSXyALhBdr8vLUnCjkG7-j2UV8\", "
    "\"q\": \"4gPgtf7FT91-FmkkNsrpK0J4Fp8jG1N0GuM30NvS4D715NWOKeuoUi1Ius3yHNdzo9uwLJgY7xJMJlr3ZSmcldwFLBKGVkLctOVLqDWrBLMwD-fPkQVV1FeRfso9bMUcprvSI2RbmIccF02MuLprltmbTdgOJA47_OqjmkHYV-U\", "
    "\"dp\": \"VIJbae8iSoicfsaBQssFYgGgYq36ckp-WShNqmbK4ZwvC4cxH3HLxtUgIKBbY8cEBSctEBdwI227D-pGyJpCIWVvdOu6BJjg-c6Dc9SDavLi5u0X1N73LT2DMZpdqAwkr3wwXclPTFNw7jcOSGrkd29O0t6RgDSVp7WTGlszCtE\", "
    "\"dq\": \"ZWB_5qJENrKO39aBW-Jf-_twihUPVi50oarRWml_iP40pVP01HDTqyiMut2tf6pUQGdF-nqulG2Mopei6Ell5wItf7s_bmnHPYysBuMrtov5PuknfVD7UqeEp25nZuZzF4aflyhovV29B-bM-_8CS0OIGb6TeTC5T5SflY17UNE\", "
    "\"qi\": \"RowmdelfiEBdqfBCSb3yblUKhwJsbyg6HtcugIVOC1yDxD5sZ0cjJPnXj7TJkrC0tICQ50MlPY5F650D9pvACIYnvrGEwsq757Lxg5nqshvuSC-7i1TMkv7_uPBmIxRfzqsnh_hVhxLgSUW1NI6_ncwk9vDQqpkY6qBirgvbyO0\" }";

// a JWS encrypted with the above JWK_COMMON key
static const char *JWS_COMMON = 
        "eyAiYWxnIjogIlBTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.0YJo4r9gbI2nZ2_1_KLTY3i5SRcZvahRuToavqBvLbm87pN7IYx8YV9kwKQclMW2ASpbEAzKNIJfQ3FycobRwZGtqCI9sRUo0vQvkpb3HIS6HKp3Kvur57J7LcZhz7uNIxzUYNQSg4EWpwhF9FnGng7bmU8qjNPiXCWfQ-n74gopAVzd3KDJ5ai7q66voRc9pCKJVbsaIMHIqcl9OPiMdY5Hz3_PgBalR2632HOdpUlIMvnMOL3EQICvyBwxaYPbhMcCpEc3_4K-sywOGiCSp9KlaLcRq0knZtAT0ynJszaiOwfR-W18PEFLfGclpeR6e_gop9mq69t36wK7KRUjrQ";

// the plaintext payload of the above JWS_COMMON
static const char *PLAIN_COMMON = 
        "If you reveal your secrets to the wind, you should not blame the "
         "wind for revealing them to the trees. — Kahlil Gibran";


static void _self_sign_self_verify(
        const char *plain1, const char *alg, cjose_err *err)
{
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // set header for JWS
    cjose_header_t *hdr = cjose_header_new(err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, alg, err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // create the JWS
    size_t plain1_len = strlen(plain1);
    cjose_jws_t *jws1 = cjose_jws_sign(jwk, hdr, plain1, plain1_len, err);
    ck_assert_msg(NULL != jws1, "cjose_jws_sign failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // get the compact serialization of JWS
    char *compact = NULL;
    ck_assert_msg(
            cjose_jws_export(jws1, &compact, err),
            "cjose_jws_export failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // deserialize the compact representation to a new JWS
    cjose_jws_t *jws2 = cjose_jws_import(compact, strlen(compact), err);
    ck_assert_msg(NULL != jws2, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // verify the deserialized JWS
    ck_assert_msg(cjose_jws_verify(jws2, jwk, err), "cjose_jws_verify failed");

    // get the verifyed plaintext
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws2, &plain2, &plain2_len, err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err->message, err->file, err->function, err->line);

    // confirm plain2 == plain1
    ck_assert_msg(
            plain2_len == strlen(plain1),
            "length of verified plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(plain1), plain2_len);
    ck_assert_msg(
            strncmp(plain1, plain2, plain2_len) == 0,
            "verifyed plaintext does not match signed plaintext");

    cjose_header_release(hdr);
    cjose_jws_release(jws1);
    cjose_jws_release(jws2);
    cjose_jwk_release(jwk);
}


START_TEST(test_cjose_jws_self_sign_self_verify)
{
    cjose_err err;
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify(PLAIN_COMMON, CJOSE_HDR_ALG_RS256, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_short)
{
    cjose_err err;
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify("Setec Astronomy", CJOSE_HDR_ALG_RS256, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_empty)
{
    cjose_err err;
    _self_sign_self_verify("", CJOSE_HDR_ALG_PS256, &err);
    _self_sign_self_verify("", CJOSE_HDR_ALG_RS256, &err);
}
END_TEST


START_TEST(test_cjose_jws_self_sign_self_verify_many)
{
    cjose_err err;

    // sign and verify a whole lot of randomly sized payloads
    for (int i = 0; i < 500; ++i)
    {
        size_t len = random() % 1024;
        char *plain = (char *)malloc(len);
        ck_assert_msg(RAND_bytes(plain, len) == 1, "RAND_bytes failed");
        plain[len-1] = 0;
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_PS256, &err);
        _self_sign_self_verify(plain, CJOSE_HDR_ALG_RS256, &err);
        free(plain);
    }
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_header)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *plain = 
        "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    static const char *JWK = 
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }";

    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWS with bad alg
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, "Cayley-Purser", &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // create a JWS
    jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad header");
    ck_assert_msg(errno == EINVAL, "cjose_jws_sign returned bad errno");

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_key)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *plain = 
        "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing public part 'e' needed for signion
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
        "\"d\": \"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\" }",

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // attempt signion with each bad key
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk = cjose_jwk_import(
                JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

        jws = cjose_jws_sign(jwk, hdr, plain, plain_len, &err);
        ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
        ck_assert_msg(errno == EINVAL, "cjose_jws_sign returned bad errno");

        cjose_jwk_release(jwk);
    }

    jws = cjose_jws_sign(NULL, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with bad key");
    ck_assert_msg(errno == EINVAL, "cjose_jws_sign returned bad errno");

    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jws_sign_with_bad_content)
{
    cjose_err err;
    cjose_header_t *hdr = NULL;
    cjose_jws_t *jws = NULL;

    static const char *JWK = 
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"d\": \"B1vTivz8th6yaKzdUusBH4dPTbyOWr6gg07K6siYKeFU7kBI5fkw4XZPWk2AjxdBB37PNBl127g25owL-twRaSrBdF5quxzzDix4fEgo77Ik9x8IcUaI5AvpMW7Ig5O0n1SRE-ZfV7KssO0Imqq6bBZkEpzfgVC760tmSuqJ0W2on8eWzi36zuKru9qA5uo7L8w9I5rzqY7XEaak0PYFi5zB1BkpI83tN2bBP2jPsym9lMP4fbf-duHgu0s9H4mDeQFyb7OuI_P7AyH3V3qhUAvk37w-HNL-17g7OBYsZK5jMwa7LobO8Tw0ZdPk5u6dWKdmiWOUUScQVAqtaDjRIQ\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWS
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_PS256, &err),
            "cjose_header_set failed");

    jws = cjose_jws_sign(jwk, hdr, NULL, 1024, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(errno == EINVAL, "cjose_jws_sign returned bad errno");

    jws = cjose_jws_sign(jwk, hdr, NULL, 0, &err);
    ck_assert_msg(NULL == jws, "cjose_jws_sign created with NULL plaintext");
    ck_assert_msg(errno == EINVAL, "cjose_jws_sign returned bad errno");

    cjose_jwk_release(jwk);
    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jws_import_export_compare)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // re-export the jws object
    const char *cser = NULL;
    ck_assert_msg(
            cjose_jws_export(jws, &cser, &err),
            "re-export of imported JWS faied: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // compare the re-export to the original serialization
    ck_assert_msg(
            strncmp(JWS_COMMON, cser, strlen(JWS_COMMON)) == 0,
            "export of imported JWS doesn't match original");

    cjose_jwk_release(jwk);
    cjose_jws_release(jws);
}
END_TEST


START_TEST(test_cjose_jws_import_invalid_serialization)
{
    cjose_err err;

    static const char *JWS_BAD[] = {
        "eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.x",
        "eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg.",
        "eyAiYWxnIjogIkhTMjU2IiB9..SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
        ".eyAiYWxnIjogIkhTMjU2IiB9.SWYgeW91IHJldmVhbCB5b3VyIHNlY3JldHMgdG8gdGhlIHdpbmQsIHlvdSBzaG91bGQgbm90IGJsYW1lIHRoZSB3aW5kIGZvciByZXZlYWxpbmcgdGhlbSB0byB0aGUgdHJlZXMuIOKAlCBLYWhsaWwgR2licmFu.KR6Ax37YPaVYjX56frkw_-cn43uBrGFj28sUCHfnQ5hq8SbxpwbsjvqT-TUUqjAa8QGAV9dVcSQzYDE1sJjvAYlpjWVb_ksiWaNo9CuoT14V08Q9kbfMlSncDS7bTILU6ywYVXnU2-X6I-_M0s2JCE8Mx4nBoUcZXtjlh2mn4iNpshG4N3EiCbCMZnHc4wRo5Pwt3GpppyutpLZlpBcXKJk42dNpKvQnxzYulig6OIgNwv6c9SEW-3qG2FJW-eFcTuFSCnAqTYBU2V-l5pa2huoHzbwHp2PeXANz4ckyJ1SGVGHHjEPIr5UXBS2HfSTxVVLHZzm1NXDs9_mqzCtpvg",
        "AAAA.BBBB",
        "AAAA",
        "",
        "..",
        NULL
    };

    for (int i = 0; NULL != JWS_BAD[i]; ++i)
    {
        cjose_jws_t *jws = cjose_jws_import(JWS_BAD[i],strlen(JWS_BAD[i]),&err);
        ck_assert_msg(NULL == jws, "cjose_jws_import of bad JWS succeeded");
        ck_assert_msg(errno == EINVAL, "cjose_jws_import returned wrong errno");
    }
}
END_TEST


START_TEST(test_cjose_jws_import_get_plain_before_verify)
{
    cjose_err err;

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
            "cjose_jws_get_plaintext before verify failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    cjose_jws_release(jws);
}
END_TEST


START_TEST(test_cjose_jws_import_get_plain_after_verify)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // derypt the imported jws
    ck_assert_msg(cjose_jws_verify(jws, jwk, &err), "cjose_jws_verify failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // get plaintext from imported and verifyed jws
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ck_assert_msg(
            cjose_jws_get_plaintext(jws, &plaintext, &plaintext_len, &err),
            "cjose_jws_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // compare the verifyed plaintext to the expected value
    ck_assert_msg(
            strncmp(PLAIN_COMMON, plaintext, strlen(PLAIN_COMMON)) == 0,
            "verifyed plaintext from JWS doesn't match the original");

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST


START_TEST(test_cjose_jws_verify_bad_params)
{
    cjose_err err;

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for signion
        "{ \"kty\": \"RSA\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\" }",

        // currently unsupported key type (EC)
        "{ \"kty\": \"EC\", \"crv\": \"P-256\", "
        "\"x\": \"VoFkf6Wk5kDQ1ob6csBmiMPHU8jALwdtaap35Fsj20M\", "
        "\"y\": \"XymwN6u2PmsKbIPy5iij6qZ-mIyej5dvZWB_75lnRgQ\", "
        "\"kid\": \"4E34BAFD-E5D9-479C-964D-009C419C38DB\" }",

        NULL
    };

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_COMMON, strlen(JWK_COMMON), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jws created with the common key
    cjose_jws_t *jws = cjose_jws_import(JWS_COMMON, strlen(JWS_COMMON), &err);
    ck_assert_msg(NULL != jws, "cjose_jws_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // try to verify a NULL jws
    ck_assert_msg(!cjose_jws_verify(NULL, jwk, &err), 
            "cjose_jws_verify succeeded with NULL jws");
    ck_assert_msg(errno == EINVAL, "cjose_jws_verify returned wrong errno");

    // try to verify with a NULL jwk
    ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), 
            "cjose_jws_verify succeeded with NULL jwk");
    ck_assert_msg(errno == EINVAL, "cjose_jws_verify returned wrong errno");

    // try to verify with bad/wrong/unsupported keys
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk_bad = cjose_jwk_import(
                JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk_bad, "cjose_jwk_import failed");

        ck_assert_msg(!cjose_jws_verify(jws, NULL, &err), 
                "cjose_jws_verify succeeded with bad jwk");
        ck_assert_msg(errno == EINVAL, "cjose_jws_verify returned wrong errno");

        cjose_jwk_release(jwk_bad);
    }

    cjose_jws_release(jws);
    cjose_jwk_release(jwk);
}
END_TEST


Suite *cjose_jws_suite()
{
    Suite *suite = suite_create("jws");

    TCase *tc_jws = tcase_create("core");
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_short);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_empty);
    tcase_add_test(tc_jws, test_cjose_jws_self_sign_self_verify_many);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_header);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_key);
    tcase_add_test(tc_jws, test_cjose_jws_sign_with_bad_content);
    tcase_add_test(tc_jws, test_cjose_jws_import_export_compare);
    tcase_add_test(tc_jws, test_cjose_jws_import_invalid_serialization);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_before_verify);
    tcase_add_test(tc_jws, test_cjose_jws_import_get_plain_after_verify);
    tcase_add_test(tc_jws, test_cjose_jws_verify_bad_params);
    suite_add_tcase(suite, tc_jws);

    return suite;
}
