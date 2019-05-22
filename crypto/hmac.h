#ifndef HMAC___H
#define HMAC___H

#include <stddef.h>
#include "sha1.h"

#define HMAC_PAD_LENGTH 64

typedef struct 
{
    tpm_sha1_t sha1;
    uint8_t    opad[HMAC_PAD_LENGTH];
} tpm_hmac_t;

#ifdef __cplusplus
extern "C" {
#endif

    void tpm_hmac_init  (tpm_hmac_t *hmac, const uint8_t *key, size_t key_len);
    void tpm_hmac_update(tpm_hmac_t *hmac, const uint8_t *data, size_t length);
    void tpm_hmac_final (tpm_hmac_t *hmac, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* _HMAC_H_ */

