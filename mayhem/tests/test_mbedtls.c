#define MBEDTLS_ALLOW_PRIVATE_ACCESS
/* Known-answer tests for the vendored mbedTLS: SHA-256 and AES vectors, X.509 certificate/CRL parsing.
 * Usage: test_mbedtls <mbedtls-data_files-dir> */
#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"

static int pass, fail;
static void report(const char *name, int ok) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  ok ? pass++ : fail++;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  char path[1024], buf[1024];

  unsigned char h[32];
  static const unsigned char want_sha[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  report("sha256_abc", mbedtls_sha256((const unsigned char *)"abc", 3, h, 0) == 0 && memcmp(h, want_sha, 32) == 0);

  /* FIPS-197 appendix C.1 AES-128 */
  static const unsigned char key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  static const unsigned char pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  static const unsigned char ct[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
  unsigned char out[16];
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int ok = mbedtls_aes_setkey_enc(&aes, key, 128) == 0 && mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, pt, out) == 0 && memcmp(out, ct, 16) == 0;
  mbedtls_aes_free(&aes);
  report("aes128_ecb_fips197", ok);

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  snprintf(path, sizeof path, "%s/server1.crt", argv[1]);
  ok = mbedtls_x509_crt_parse_file(&crt, path) == 0;
  report("x509_crt_parse_server1", ok);
  if (ok) {
    mbedtls_x509_dn_gets(buf, sizeof buf, &crt.subject);
    report("x509_subject_server1", strcmp(buf, "C=NL, O=PolarSSL, CN=PolarSSL Server 1") == 0);
    report("x509_version_serial", crt.version == 3 && crt.serial.len == 1 && crt.serial.p[0] == 1);
    report("x509_sig_alg_sha1", crt.sig_md == MBEDTLS_MD_SHA1);
  } else {
    report("x509_subject_server1", 0); report("x509_version_serial", 0); report("x509_sig_alg_sha1", 0);
  }
  mbedtls_x509_crt_free(&crt);

  mbedtls_x509_crl crl;
  mbedtls_x509_crl_init(&crl);
  snprintf(path, sizeof path, "%s/crl.pem", argv[1]);
  ok = mbedtls_x509_crl_parse_file(&crl, path) == 0;
  report("x509_crl_parse", ok && crl.version == 1 && crl.entry.serial.len == 1 && crl.entry.serial.p[0] == 1);
  mbedtls_x509_crl_free(&crl);

  mbedtls_x509_crt bad;
  mbedtls_x509_crt_init(&bad);
  report("x509_crt_reject_garbage", mbedtls_x509_crt_parse(&bad, (const unsigned char *)"not a certificate", 18) != 0);
  mbedtls_x509_crt_free(&bad);

  printf("SUMMARY pass=%d fail=%d\n", pass, fail);
  return fail != 0;
}
