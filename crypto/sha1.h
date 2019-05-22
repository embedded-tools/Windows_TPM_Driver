#ifndef SHA1___H
#define SHA1___H

#include "datatypes.h"

#define SHA1_DIGEST_LENGTH 20

typedef struct 
{
  uint32_t h[5];
  uint32_t count_lo, count_hi;
  uint8_t buf[64];
} tpm_sha1_t;

#ifdef __cplusplus
extern "C" {
#endif

void tpm_sha1_init(tpm_sha1_t *sha);
void tpm_sha1_update(tpm_sha1_t *sha, const uint8_t *data, size_t length);
void tpm_sha1_update_be32(tpm_sha1_t *sha, uint32_t data);
void tpm_sha1_final(tpm_sha1_t *sha, uint8_t digest[SHA1_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif /* _SHA1_H_ */
