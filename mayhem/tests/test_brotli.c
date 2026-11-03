/* Known-answer test: brotli-decode upstream's reference *.compressed files and compare byte-for-byte
 * against the plain originals. Usage: test_brotli <brotli-testdata-dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/decode.h>

static int pass, fail;

static uint8_t *slurp(const char *path, size_t *n) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc(sz ? sz : 1);
  *n = fread(b, 1, sz, f); fclose(f);
  return b;
}

static void check(const char *dir, const char *name) {
  char p1[1024], p2[1024];
  snprintf(p1, sizeof p1, "%s/%s", dir, name);
  snprintf(p2, sizeof p2, "%s/%s.compressed", dir, name);
  size_t plain_n = 0, comp_n = 0;
  uint8_t *plain = slurp(p1, &plain_n), *comp = slurp(p2, &comp_n);
  int ok = 0;
  if (plain && comp) {
    size_t out_n = plain_n + 64;
    uint8_t *out = malloc(out_n);
    BrotliDecoderResult r = BrotliDecoderDecompress(comp_n, comp, &out_n, out);
    ok = (r == BROTLI_DECODER_RESULT_SUCCESS && out_n == plain_n && memcmp(out, plain, plain_n) == 0);
    free(out);
  }
  printf("%s brotli_decode_%s\n", ok ? "PASS" : "FAIL", name);
  ok ? pass++ : fail++;
  free(plain); free(comp);
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  const char *names[] = {"10x10y", "64x", "empty", "x", "xyzzy", "zeros", "quickfox", "quickfox_repeated",
                         "monkey", "ukkonooa", "alice29.txt", "asyoulik.txt", "random_org_10k.bin"};
  for (size_t i = 0; i < sizeof names / sizeof *names; i++) check(argv[1], names[i]);
  printf("SUMMARY pass=%d fail=%d\n", pass, fail);
  return fail != 0;
}
