/*!
 *
 */

#include "check_cjose.h"

#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include <cjose/cjose.h>
#include <jansson.h>
#include "include/jwk_int.h"
#include "include/jwe_int.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>


// a JWK of type RSA
static const char *JWK_RSA = 
    "{ \"kty\": \"RSA\", "
    "\"e\": \"AQAB\", "
    "\"n\": \"wsqJbopx18NQFYLYOq4ZeMSE89yGiEankUpf25yV8QqroKUGrASj_OeqTWUjwPGKTN1vGFFuHYxiJeAUQH2qQPmg9Oqk6-ATBEKn9COKYniQ5459UxCwmZA2RL6ufhrNyq0JF3GfXkjLDBfhU9zJJEOhknsA0L_c-X4AI3d_NbFdMqxNe1V_UWAlLcbKdwO6iC9fAvwUmDQxgy6R0DC1CMouQpenMRcALaSHar1cm4K-syoNobv3HEuqgZ3s6-hOOSqauqAO0GUozPpaIA7OeruyRl5sTWT0r-iz39bchID2bIKtcqLiFcSYPLBcxmsaQCqRlGhmv6stjTCLV1yT9w\", "
    "\"kid\": \"ff3c5c96-392e-46ef-a839-6ff16027af78\", "
    "\"d\": \"b9hXfQ8lOtw8mX1dpqPcoElGhbczz_-xq2znCXQpbBPSZBUddZvchRSH5pSSKPEHlgb3CSGIdpLqsBCv0C_XmCM9ViN8uqsYgDO9uCLIDK5plWttbkqA_EufvW03R9UgIKWmOL3W4g4t-C2mBb8aByaGGVNjLnlb6i186uBsPGkvaeLHbQcRQKAvhOUTeNiyiiCbUGJwCm4avMiZrsz1r81Y1Z5izo0ERxdZymxM3FRZ9vjTB-6DtitvTXXnaAm1JTu6TIpj38u2mnNLkGMbflOpgelMNKBZVxSmfobIbFN8CHVc1UqLK2ElsZ9RCQANgkMHlMkOMj-XT0wHa3VBUQ\", "
    "\"p\": \"8mgriveKJAp1S7SHqirQAfZafxVuAK_A2QBYPsAUhikfBOvN0HtZjgurPXSJSdgR8KbWV7ZjdJM_eOivIb_XiuAaUdIOXbLRet7t9a_NJtmX9iybhoa9VOJFMBq_rbnbbte2kq0-FnXmv3cukbC2LaEw3aEcDgyURLCgWFqt7M0\", "
    "\"q\": \"zbbTv5421GowOfKVEuVoA35CEWgl8mdasnEZac2LWxMwKExikKU5LLacLQlcOt7A6n1ZGUC2wyH8mstO5tV34Eug3fnNrbnxFUEE_ZB_njs_rtZnwz57AoUXOXVnd194seIZF9PjdzZcuwXwXbrZ2RSVW8if_ZH5OVYEM1EsA9M\", "
    "\"dp\": \"1BaIYmIKn1X3InGlcSFcNRtSOnaJdFhRpotCqkRssKUx2qBlxs7ln_5dqLtZkx5VM_UE_GE7yzc6BZOwBxtOftdsr8HVh-14ksSR9rAGEsO2zVBiEuW4qZf_aQM-ScWfU--wcczZ0dT-Ou8P87Bk9K9fjcn0PeaLoz3WTPepzNE\", "
    "\"dq\": \"kYw2u4_UmWvcXVOeV_VKJ5aQZkJ6_sxTpodRBMPyQmkMHKcW4eKU1mcJju_deqWadw5jGPPpm5yTXm5UkAwfOeookoWpGa7CvVf4kPNI6Aphn3GBjunJHNpPuU6w-wvomGsxd-NqQDGNYKHuFFMcyXO_zWXglQdP_1o1tJ1M-BM\", "
    "\"qi\": \"j94Ens784M8zsfwWoJhYq9prcSZOGgNbtFWQZO8HP8pcNM9ls7YA4snTtAS_B4peWWFAFZ0LSKPCxAvJnrq69ocmEKEk7ss1Jo062f9pLTQ6cnhMjev3IqLocIFt5Vbsg_PWYpFSR7re6FRbF9EYOM7F2-HRv1idxKCWoyQfBqk\" }";

// a JWK of type oct
static const char *JWK_OCT = 
        "{\"kty\":\"oct\", "
        "\"k\":\"ZMpktzGq1g6_r4fKVdnx9OaYr4HjxPjIs7l7SwAsgsg\"}";

// a JWE encrypted with the above JWK_RSA key (using node-jose)
static const char *JWE_RSA = 
        "eyJraWQiOiJmZjNjNWM5Ni0zOTJlLTQ2ZWYtYTgzOS02ZmYxNjAyN2FmNzgiLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.FGQ9IUhjmSJr4dAntH0DP-dAJiZPfKCRhg-SjUywNFqmG-ruhRvio1K7qy2Z0joatZxdJmkOInlsGvGIZeyapTtOndshCsfTlazHH-4fqFyepIm6o-gZ8gfntDG_sa9hi9uw1KxeJfNmaL94JMjq-QVmocdCeruIE7_bL90MNflQ8qf5vhuh_hF_Ea_vUnHlIbbQsF1ZF4rRsEGBR7CxTBxusMgErct0kp3La6qQbnX8fDJMqL_aeot4xZRm3zobIYqKePaGBaSJ7wooWslM1w57IrYXN0UVODRAFO6L5ldF_PHpWbBnFx4k_-FWCOVb-iVpQmLtBkniKG6iItXVUQ.ebcXmjWfUMq-brIT.BPt7F9tcIwQpoAjlyguagOGftJE392-j3kSnP5I6nB-WhWKfpPAeChIW23oWTUHlUbadOeBaiI6r-2TLTZzf3jFKc8Wwr-F0q_iEUQjmg3om-PKR_Pgl_ncDTXjkxSQjbHOAV1JByh61G-WFuEC1UItyib0AOq9R.Mlo2kQF8Zn2hwwdDl_4Lnw";

// the plaintext payload of the above JWE object(s)
static const char *PLAINTEXT = 
        "If you reveal your secrets to the wind, you should not blame the "
        "wind for revealing them to the trees. — Kahlil Gibran";


START_TEST(test_cjose_jwe_node_jose_encrypt_self_decrypt)
{
    cjose_err err;

    // import the JWK
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the JWE
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe, "cjose_jwe_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // decrypt the imported JWE
    size_t plain2_len = 0;
    uint8_t *plain2 = cjose_jwe_decrypt(jwe, jwk, &plain2_len, &err);
    ck_assert_msg(
            NULL != plain2,
            "cjose_jwe_get_plaintext failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // confirm plain2 == PLAINTEXT
    ck_assert_msg(
            plain2_len == strlen(PLAINTEXT),
            "length of decrypted plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(PLAINTEXT), plain2_len);
    ck_assert_msg(
            strncmp(PLAINTEXT, plain2, plain2_len) == 0,
            "decrypted plaintext does not match encrypted plaintext");

    cjose_jwk_release(jwk);
    cjose_jwe_release(jwe);
}
END_TEST


static void _self_encrypt_self_decrypt_with_key(
        const char *alg,
        const char *enc,
        const char *key,
        const char *plain1)
{
    cjose_err err;

    cjose_jwk_t *jwk = cjose_jwk_import(key, strlen(key), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWE
    cjose_header_t *hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ENC, enc, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // create the JWE
    size_t plain1_len = strlen(plain1);
    cjose_jwe_t *jwe1 = cjose_jwe_encrypt(jwk, hdr, plain1, plain1_len, &err);
    ck_assert_msg(NULL != jwe1, 
            "cjose_jwe_encrypt failed: %s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // get the compact serialization of JWE
    char *compact = cjose_jwe_export(jwe1, &err);
    ck_assert_msg(NULL != compact,
            "cjose_jwe_export failed: %s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // deserialize the compact representation to a new JWE
    cjose_jwe_t *jwe2 = cjose_jwe_import(compact, strlen(compact), &err);
    ck_assert_msg(NULL != jwe2, "cjose_jwe_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // get the decrypted plaintext
    uint8_t *plain2 = NULL;
    size_t plain2_len = 0;
    plain2 = cjose_jwe_decrypt(jwe2, jwk, &plain2_len, &err);
    ck_assert_msg(
            NULL != plain2, "cjose_jwe_decrypt failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // confirm plain2 == plain1
    ck_assert_msg(
            plain2_len == strlen(plain1),
            "length of decrypted plaintext does not match length of original, "
            "expected: %lu, found: %lu", strlen(plain1), plain2_len);
    ck_assert_msg(
            strncmp(plain1, plain2, plain2_len) == 0,
            "decrypted plaintext does not match encrypted plaintext");

    cjose_header_release(hdr);
    cjose_jwe_release(jwe1);
    cjose_jwe_release(jwe2);
    cjose_jwk_release(jwk);
    free(compact);
}


static void _self_encrypt_self_decrypt(const char *plain1)
{
    _self_encrypt_self_decrypt_with_key(
            CJOSE_HDR_ALG_RSA_OAEP, 
            CJOSE_HDR_ENC_A256GCM, 
            JWK_RSA, 
            plain1);

    _self_encrypt_self_decrypt_with_key(
            CJOSE_HDR_ALG_DIR, 
            CJOSE_HDR_ENC_A256GCM, 
            JWK_OCT, 
            plain1); 
}


START_TEST(test_cjose_jwe_self_encrypt_self_decrypt)
{
    _self_encrypt_self_decrypt(
        "Sed ut perspiciatis unde omnis iste natus error sit voluptatem "
        "doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo "
        "veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo "
        "ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed "
        "consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. "
        "porro quisquam est, qui dolorem ipsum quia dolor sit amet, "
        "adipisci velit, sed quia non numquam eius modi tempora incidunt ut "
        "dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, "
        "nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut "
        "ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in "
        "voluptate velit esse quam nihil molestiae consequatur, vel illum qui "
        "eum fugiat quo voluptas nulla pariatur?");
}
END_TEST


START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_short)
{
    _self_encrypt_self_decrypt("Setec Astronomy");
}
END_TEST


START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_empty)
{
    _self_encrypt_self_decrypt("");
}
END_TEST


START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_large)
{
    // encrypt and decrypt a 4MB buffer of z's
    size_t len = 1024*4096;
    char *plain = (char *)malloc(len);
    memset(plain, 'z', len);
    plain[len-1] = 0;
    _self_encrypt_self_decrypt(plain);
    free(plain);
}
END_TEST


START_TEST(test_cjose_jwe_self_encrypt_self_decrypt_many)
{
    // encrypt and decrypt a whole lot of randomly sized payloads
    for (int i = 0; i < 500; ++i)
    {
        size_t len = random() % 1024;
        char *plain = (char *)malloc(len);
        ck_assert_msg(RAND_bytes(plain, len) == 1, "RAND_bytes failed");
        plain[len-1] = 0;
        _self_encrypt_self_decrypt(plain);
        free(plain);
    }
}
END_TEST

START_TEST(test_cjose_jwe_encrypt_with_bad_header)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

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

    // set header for JWE with bad alg
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, "Cayley-Purser", &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // create a JWE
    jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_encrypt returned bad err.code");

    // set header for JWE with bad enc
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ENC, "Twofish", &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // create a JWE
    jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad header");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_encrypt returned bad err.code");

    cjose_header_release(hdr);
    cjose_jwk_release(jwk);
}
END_TEST

START_TEST(test_cjose_jwe_encrypt_with_bad_key)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

    static const char *plain = 
        "The mind is everything. What you think you become.";
    size_t plain_len = strlen(plain);

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing public part 'e' needed for encryption
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

    // set header for JWE
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // attempt encryption with each bad key
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk = cjose_jwk_import(
                    JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

        jwe = cjose_jwe_encrypt(jwk, hdr, plain, plain_len, &err);
        ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad key");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
                "cjose_jwe_encrypt returned bad err.code");

        cjose_jwk_release(jwk);
    }

    jwe = cjose_jwe_encrypt(NULL, hdr, plain, plain_len, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with bad key");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_encrypt returned bad err.code");

    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jwe_encrypt_with_bad_content)
{
    cjose_header_t *hdr = NULL;
    cjose_jwe_t *jwe = NULL;
    cjose_err err;

    static const char *JWK = 
        "{ \"kty\": \"RSA\", "
        "\"kid\": \"9ebf9edb-3a24-48b4-b2cb-21f0cf747ea7\", "
        "\"e\": \"AQAB\", "
        "\"n\": \"0a5nKJLjaB1xdebYWfhvlhYhgfzkw49HAUIjyvb6fNPKhwlBQMoAS5jM3kI17_OMGrHxL7ZP00OE-24__VWDCAhOQsSvlgCvw2XOOCtSWWLpb03dTrCMFeemqS4S9jrKd3NbUk3UJ2dVb_EIbQEC_BVjZStr_HcCrKsj4AluaQUn09H7TuK0yZFBzZMhJ1J8Yi3nAPkxzdGah0XuWhLObMAvANSVmHzRXwnTDw9Dh_bJ4G1xd1DE7W94uoUlcSDx59aSdzTpQzJh1l3lXc6JRUrXTESYgHpMv0O1n0gbIxX8X1ityBlMiccDjfZIKLnwz6hQObvRtRIpxEdq4SYS-w\" }";

    // import the key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK, strlen(JWK), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // set header for JWE
    hdr = cjose_header_new(&err);
    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    ck_assert_msg(
            cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err),
            "cjose_header_set failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    jwe = cjose_jwe_encrypt(jwk, hdr, NULL, 1024, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_encrypt returned bad err.code");

    jwe = cjose_jwe_encrypt(jwk, hdr, NULL, 0, &err);
    ck_assert_msg(NULL == jwe, "cjose_jwe_encrypt created with NULL plaintext");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_encrypt returned bad err.code");

    cjose_jwk_release(jwk);
    cjose_header_release(hdr);
}
END_TEST


START_TEST(test_cjose_jwe_import_export_compare)
{
    cjose_err err;

    // import the common key
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jwe created with the common key
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe, "cjose_jwe_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // re-export the jwe object
    const char *cser = cjose_jwe_export(jwe, &err);
    ck_assert_msg(NULL != cser,
            "re-export of imported JWE faied: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // compare the re-export to the original serialization
    ck_assert_msg(
            strncmp(JWE_RSA, cser, strlen(JWE_RSA)) == 0,
            "export of imported JWE doesn't match original");

    cjose_jwk_release(jwk);
    cjose_jwe_release(jwe);
    free(cser);
}
END_TEST


START_TEST(test_cjose_jwe_import_invalid_serialization)
{
    cjose_err err;

    static const char *JWE_BAD[] = {
        "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w.NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg.x",
        "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w.NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg.",
        "eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w.NnDIbUkIHi1suUKk..jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg",
        ".eyJraWQiOiI5ZWJmOWVkYi0zYTI0LTQ4YjQtYjJjYi0yMWYwY2Y3NDdlYTciLCJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.D4Od2xiHoO5SYtoUXt_I_oZvxFfCA29dxbyz21Uw6sP-uQpoPxu-jQ7NUJtmzZIf4VIWHN5YOrV0-UqKkP-Woipug26blBPkIV4YzoNFJD3sMW3Bbc91M_Rwd03QID6eGv0REkCo1KbbLnw_u56PGBtPVHJNIMwNTKdU-FJwxEkahZGU3FS8RLw8-0BeFvLbjg3yTCUVuZex2mZ3QL_sXrCYADSMpYDWC41nxEWt26Z_cxGhGmRU_5fjsE_AWHrIWS1-qdZcAlYrv-wMg0pRqsElGVVcFSkfXBfyGFURcAqB-a2ge2IxxQ-G3Jkhl7EFIWhhD1ZtQWGEpBVjHZeH3w.NnDIbUkIHi1suUKk.jUGOQ2vKzL_nrjbaK6qwnDBTtU26Ut9HiyUsblnEs_0aO0aJ50f13bu2EBic5e0e50Lu8jVUlMSfwPgfqKePV9xbHmE6GPn_E59VxnzJpMVoxohjqezkG50ydvqXg_lJ84BLk8R0dR_LtUZxJdbzNo-B8YRloiKPOee7zyZ6tU9h-_so37XgLBy6uDDeGxGlK6TnG8q9oqLB7zLF03Seyv8XBl-Bved7V8sor_sr4efoyW_oKneqqBSqnaQ0OApMnFTQ7yudwfI19R9CvYI62bfluDSknai0Lwm3cGDOSningMxKpPVja_Ieyb5cJNHsnR5u5bCYjBl5l7wL7ttXBBURaFDO6i67KxHq-K02AAxyAWkJM9DWt_IXsx4vxvYCgUQQxmMvZRAzxdrT1UOvpyJoh64LcuKuj4LGY_b6xaSV72CpeNQWXaSJDSNtQKsoO3-S4QAcqHTUXb9-_HKIi8sZJgqxeyHYs2oJRD0WItq0BUVoHvaQmR2gRm-rhXuujOWJW_xk9Wp8lpbJR8tANdcai7O84WR9noA0-z3BdYdLOftK-YAR1Fa8OEE1-VSAI7TfRjMdAMw01pGJZmwn4VhbcE60QS0uESnNPRq9abpVqVlEA6WdFtAgv6oUJ34YpSQ5hXEXbTSz0XL948q58QZ0oadVeR-1JOm3fjCgvJgvvcdmDs1kZy2iPPmMhsmwiTQCBXlgwbj7xUxuA9EtcVcIylL3X1BmRqDJG8kyJLBFvRtBwe6OC0uApr_74evzbnihMFk1bBEeL0H8yJWvWpl20SHF6gjlEHb7OqF1fMGj3oqxRjYrRcNj2EV-Acq8WVbRuizYSxREnBt5_sWoiUHtbSpgNeMEv3Go9fzVsa93KKF6llT2KBo6V8Vx4XxjmGG6U5oUS_SX1S3bnHPqepv9izstL2Stlz8_UwxqVER1aotgywX1ez70YGA37Ikr6gO9LPKCYVQtcRG7P597mka0STnYFf6arOF0DUC_hyWYLjwoiTj9QVg9JPqMuxSo8JFTpkGeNQf6slLiYc9WDd4J-QfFmSZBBguWmxq3ch_sg9YfPlBXir5oCVu3GDTZX2oH1h5gGwWHCgqM8qv2fsQoLwAZR9EhThb6zi1u12WxyLlwApw5O32GiJpOj1bWr-_69Lo4Mpc66EYdmoKDXl4qmp6b0yhCUVS9e1Miu0vsXFq2NJwP4HUUnN_FojhS1F5EYOSW8ue1K3ESyqVrKKoF5sVqGJZESiveiR5ypVpmAOSfmZltJ-GVO5cOcGKvtYG4PQz_wN7T_I0g9XWP9hBW5G0BZTR-rvT8mwobLT2ijFA_5TMkRualT2NzAttEbx7ThGwEJoU3-2k3_hqykZtfQv7KxwwYdezVsxV-ukbMfzrOsOU517tIZ9wNdf1BV4c1sINlWfllAi9Sm54KqoLyqTtzvtM54InuknS4H-mEMMK3J7geH3GKpuAz-RUiim6OKihuOJvKSsyLxRL32u-HnszlczfShAOfWA_1nfWzRYzVxtqfv3PXPQguF8A4-VhE_YSPQc6Bnwh_LzliqA-8Vk5WZiAwDN_WybhPmZg5UnwVh5x7tnBPq82HSuCU4uefjaLBfjYnfRul2UY86HlHlpXVgyZEAvhRFPQwklqcfmlf3lCFz-g6P9wKYj0uncG3T9NUs28Oksy-o9MdC3aekP-0LszrxQbfwps0nq45dVsnURJCGyT7vwCObUTPDGFCMg.B4xpiaoieUnluhz5U4ivTg",
        "AAAA.BBBB.CCCC.DDDD",
        "AAAA.BBBB.CCCC",
        "AAAA.BBBB",
        "AAAA",
        "",
        "....",
        "this test is dedicated to swhitsel",
        NULL
    };

    for (int i = 0; NULL != JWE_BAD[i]; ++i)
    {
        cjose_jwe_t *jwe = cjose_jwe_import(
                JWE_BAD[i], strlen(JWE_BAD[i]), &err);
        ck_assert_msg(
                NULL == jwe, "cjose_jwe_import of bad JWE succeeded (%d)", i);
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
                "cjose_jwe_import returned wrong err.code");
    }
}
END_TEST


START_TEST(test_cjose_jwe_decrypt_bad_params)
{
    cjose_err err;
    size_t len = 0;

    // some bad keys to test with
    static const char *JWK_BAD[] = {

        // missing private part 'd' needed for encryption
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
    cjose_jwk_t *jwk = cjose_jwk_import(JWK_RSA, strlen(JWK_RSA), &err);
    ck_assert_msg(NULL != jwk, "cjose_jwk_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // import the jwe created with the common key
    cjose_jwe_t *jwe = cjose_jwe_import(JWE_RSA, strlen(JWE_RSA), &err);
    ck_assert_msg(NULL != jwe, "cjose_jwe_import failed: "
            "%s, file: %s, function: %s, line: %ld", 
            err.message, err.file, err.function, err.line);

    // try to decrypt a NULL jwe
    ck_assert_msg(!cjose_jwe_decrypt(NULL, jwk, &len, &err), 
            "cjose_jwe_decrypt succeeded with NULL jwe");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_decrypt returned wrong err.code");

    // try to decrypt with a NULL jwk
    ck_assert_msg(!cjose_jwe_decrypt(jwe, NULL, &len, &err), 
            "cjose_jwe_decrypt succeeded with NULL jwk");
    ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
            "cjose_jwe_decrypt returned wrong err.code");

    // try to decrypt with bad/wrong/unsupported keys
    for (int i = 0; NULL != JWK_BAD[i]; ++i)
    {
        cjose_jwk_t *jwk_bad = cjose_jwk_import(
                JWK_BAD[i], strlen(JWK_BAD[i]), &err);
        ck_assert_msg(NULL != jwk_bad, "cjose_jwk_import failed");

        ck_assert_msg(!cjose_jwe_decrypt(jwe, NULL, &len, &err), 
                "cjose_jwe_decrypt succeeded with bad jwk");
        ck_assert_msg(err.code == CJOSE_ERR_INVALID_ARG, 
                "cjose_jwe_decrypt returned wrong err.code");

        cjose_jwk_release(jwk_bad);
    }

    cjose_jwe_release(jwe);
    cjose_jwk_release(jwk);
}
END_TEST


Suite *cjose_jwe_suite()
{
    Suite *suite = suite_create("jwe");

    TCase *tc_jwe = tcase_create("core");
    tcase_add_test(tc_jwe, test_cjose_jwe_node_jose_encrypt_self_decrypt);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_short);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_empty);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_large);
    tcase_add_test(tc_jwe, test_cjose_jwe_self_encrypt_self_decrypt_many);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_header);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_key);
    tcase_add_test(tc_jwe, test_cjose_jwe_encrypt_with_bad_content);
    tcase_add_test(tc_jwe, test_cjose_jwe_import_export_compare);
    tcase_add_test(tc_jwe, test_cjose_jwe_import_invalid_serialization);
    tcase_add_test(tc_jwe, test_cjose_jwe_decrypt_bad_params);
    suite_add_tcase(suite, tc_jwe);

    return suite;
}
