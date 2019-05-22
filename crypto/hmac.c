#include "hmac.h"
#include "datatypes.h"
#include <string.h>

void tpm_hmac_init(tpm_hmac_t *hmac, const uint8_t *key, size_t key_len)
{
    uint8_t tk[SHA1_DIGEST_LENGTH];
    uint8_t ipad[HMAC_PAD_LENGTH];
    int i;

    /* if key is longer than 64 bytes then reset it to key = hash(key) */
    if (key_len > HMAC_PAD_LENGTH) 
    {
        tpm_sha1_init(&hmac->sha1);
        tpm_sha1_update(&hmac->sha1, key, key_len);
        tpm_sha1_final(&hmac->sha1, tk);
        key = tk;
        key_len = SHA1_DIGEST_LENGTH;
    }

    /* start out by storing key in pads */
    memset(ipad, 0, HMAC_PAD_LENGTH);
    memset(hmac->opad, 0, HMAC_PAD_LENGTH);
    memcpy(ipad, key, key_len);
    memcpy(hmac->opad, key, key_len);

    /* xor key with ipad and opad values */
    for (i = 0; i < HMAC_PAD_LENGTH; i++) 
    {
        ipad[i] ^= 0x36;
        hmac->opad[i] ^= 0x5C;
    }

    /* start inner hash */
    tpm_sha1_init(&hmac->sha1);
    tpm_sha1_update(&hmac->sha1, ipad, HMAC_PAD_LENGTH);
}

void tpm_hmac_update(tpm_hmac_t *hmac, const uint8_t *data, size_t length)
{
    /* update inner hash */
    tpm_sha1_update(&hmac->sha1, data, length);
}

void tpm_hmac_final(tpm_hmac_t *hmac, uint8_t *digest)
{
    /* complete inner hash */
    tpm_sha1_final(&hmac->sha1, digest);

    /* perform outer hash */
    tpm_sha1_init(&hmac->sha1);
    tpm_sha1_update(&hmac->sha1, hmac->opad, HMAC_PAD_LENGTH);
    tpm_sha1_update(&hmac->sha1, digest, SHA1_DIGEST_LENGTH);
    tpm_sha1_final(&hmac->sha1, digest);
}

