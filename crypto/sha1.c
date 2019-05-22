#include "sha1.h"
#include <string.h>

#define rol(v,b) (((v) << (b)) | ((v) >> (32 - (b))))
#ifdef __BIG_ENDIAN__
#define B0(i) (buf[i] = buf[i])
#else
#define B0(i) (buf[i] = (((buf[i] & 0xff000000) >> 24) | ((buf[i] & 0x00ff0000) >> 8) |\
                         ((buf[i] & 0x0000ff00) << 8)  | ((buf[i] & 0x000000ff) << 24)))
#endif
#define B1(i) (buf[i & 15] = rol(buf[i & 15] ^ buf[(i-14) & 15] ^ buf[(i-8) & 15] ^ buf[(i-3) & 15], 1))
#define F0(x,y,z) ((x & (y ^ z)) ^ z)
#define F1(x,y,z) (x ^ y ^ z)
#define F2(x,y,z) (((x | y) & z) | (x & y))
#define R0(a,b,c,d,e,i) e += F0(b,c,d) + B0(i) + 0x5A827999 + rol(a,5); b = rol(b,30);
#define R1(a,b,c,d,e,i) e += F0(b,c,d) + B1(i) + 0x5A827999 + rol(a,5); b = rol(b,30);
#define R2(a,b,c,d,e,i) e += F1(b,c,d) + B1(i) + 0x6ED9EBA1 + rol(a,5); b = rol(b,30);
#define R3(a,b,c,d,e,i) e += F2(b,c,d) + B1(i) + 0x8F1BBCDC + rol(a,5); b = rol(b,30);
#define R4(a,b,c,d,e,i) e += F1(b,c,d) + B1(i) + 0xCA62C1D6 + rol(a,5); b = rol(b,30);

static void tpm_sha1_transform(uint32_t h[5], const uint8_t data[64])
{
  uint32_t a, b, c, d, e;
  uint32_t buf[16];

  /* copy state and data*/
  a = h[0];
  b = h[1];
  c = h[2];
  d = h[3];
  e = h[4];

  memcpy(buf, data, 64);

  /* unrolled sha-1 rounds */
  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

  /* update state */
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;

  /* overwrite all used variables */
  a = b = c = d = e = 0;
  memset(buf, 0, 64);
}


void tpm_sha1_init(tpm_sha1_t *sha)
{
    /* initialise with sha-1 constants */
    sha->h[0] = 0x67452301;
    sha->h[1] = 0xEFCDAB89;
    sha->h[2] = 0x98BADCFE;
    sha->h[3] = 0x10325476;
    sha->h[4] = 0xC3D2E1F0;

    sha->count_lo = sha->count_hi = 0;
}

void tpm_sha1_update(tpm_sha1_t *sha, const uint8_t *data, size_t length)
{
    size_t buf_off = (sha->count_lo >> 3) & 63;
    size_t data_off = 0;

    /* add data */
    if (length + buf_off >= 64) 
    {
        data_off = 64 - buf_off;
        memcpy(&sha->buf[buf_off], data, data_off);
        tpm_sha1_transform(sha->h, sha->buf);
        while (data_off + 64 <= length) 
        { 
            tpm_sha1_transform(sha->h, &data[data_off]);
            data_off += 64;
        }
        buf_off = 0;
    }
    memcpy(&sha->buf[buf_off], &data[data_off], length - data_off);

    /* update counter */
    buf_off = sha->count_lo;
    sha->count_lo += length << 3;
    if (sha->count_lo < buf_off) sha->count_hi++;
    sha->count_hi += length >> 29;
}

void tpm_sha1_update_be32(tpm_sha1_t *sha, uint32_t data)
{
    uint8_t buf[4];

    buf[0] = (data >> 24) & 0xff;
    buf[1] = (data >> 16) & 0xff;
    buf[2] = (data >>  8) & 0xff;
    buf[3] = (data >>  0) & 0xff;

    tpm_sha1_update(sha, buf, 4);
}

void tpm_sha1_final(tpm_sha1_t *sha, uint8_t digest[SHA1_DIGEST_LENGTH])
{
    uint8_t d, counter[8];

    /* setup counter */
    for (d = 0; d < 4; d++) 
    {
        counter[d]   = (sha->count_hi >> (24 - d * 8)) & 0xff;
        counter[d+4] = (sha->count_lo >> (24 - d * 8)) & 0xff;
    }

    /* add padding */
    d = 0x80;
    tpm_sha1_update(sha, &d, 1);

    d = 0x00;
    while ((sha->count_lo & (63 * 8)) != (56 * 8)) 
    {
        tpm_sha1_update(sha, &d, 1);
    }

    /* add counter */
    tpm_sha1_update(sha, counter, 8);
    for (d = 0; d < SHA1_DIGEST_LENGTH; d++) 
    {
        digest[d] = (uint8_t)(sha->h[d >> 2] >> (8 * (3 - (d & 3))) & 0xff);
    }

    /* overwrite all used variables */
    memset(sha, 0, sizeof(*sha));
    memset(counter, 0, sizeof(counter));
}
