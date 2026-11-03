/* Known-answer tests for the vendored oniguruma: compile, search, capture offsets. */
#include <stdio.h>
#include <string.h>
#include <oniguruma.h>

static int pass, fail;
static void report(const char *name, int ok) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  ok ? pass++ : fail++;
}

static int search(const char *pat, const char *str, OnigRegion *reg, regex_t **out, OnigSyntaxType *syn) {
  OnigEncoding enc = ONIG_ENCODING_UTF8;
  if (onig_new(out, (const UChar *)pat, (const UChar *)pat + strlen(pat), ONIG_OPTION_DEFAULT, enc, syn, NULL) != ONIG_NORMAL)
    return -100;
  const UChar *s = (const UChar *)str, *e = s + strlen(str);
  return onig_search(*out, s, e, s, e, reg, ONIG_OPTION_NONE);
}

int main(void) {
  OnigEncoding use = ONIG_ENCODING_UTF8;
  onig_initialize(&use, 1);
  regex_t *re; OnigRegion *reg = onig_region_new();

  int r = search("a(b+)c", "xxabbbcx", reg, &re, ONIG_SYNTAX_DEFAULT);
  report("match_pos", r == 2);
  report("match_end", reg->end[0] == 7);
  report("capture_group", reg->num_regs == 2 && reg->beg[1] == 3 && reg->end[1] == 6);
  onig_free(re);

  r = search("(?i)h[e]LLo", "say HELLO", reg, &re, ONIG_SYNTAX_DEFAULT);
  report("ignore_case", r == 4);
  onig_free(re);

  r = search("\\p{Greek}+", "ab \xce\xb1\xce\xb2\xce\xb3 cd", reg, &re, ONIG_SYNTAX_DEFAULT);
  report("unicode_property", r == 3 && reg->end[0] == 9);
  onig_free(re);

  r = search("zzz", "no such text", reg, &re, ONIG_SYNTAX_DEFAULT);
  report("no_match", r == ONIG_MISMATCH);
  onig_free(re);

  regex_t *bad; OnigErrorInfo ei;
  const char *p = "a(b";
  r = onig_new(&bad, (const UChar *)p, (const UChar *)p + 3, ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &ei);
  report("reject_unbalanced", r == ONIGERR_END_PATTERN_WITH_UNMATCHED_PARENTHESIS);

  onig_region_free(reg, 1);
  onig_end();
  printf("SUMMARY pass=%d fail=%d\n", pass, fail);
  return fail != 0;
}
