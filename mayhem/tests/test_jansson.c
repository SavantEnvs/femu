/* Known-answer tests for the vendored jansson: load -> inspect -> dump. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

static int pass, fail;
static void report(const char *name, int ok) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  ok ? pass++ : fail++;
}

int main(void) {
  json_error_t err;
  json_t *root = json_loads("{\"b\":[1,2,{\"z\":null}],\"a\":\"x\\u00e9\",\"n\":-12.5e1}", 0, &err);
  report("load_object", root && json_is_object(root));
  if (root) {
    report("array_len", json_array_size(json_object_get(root, "b")) == 3);
    report("int_elem", json_integer_value(json_array_get(json_object_get(root, "b"), 1)) == 2);
    report("real_val", json_real_value(json_object_get(root, "n")) == -125.0);
    report("utf8_string", strcmp(json_string_value(json_object_get(root, "a")), "x\xc3\xa9") == 0);
    char *s = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    report("dump_compact_sorted", s && strcmp(s, "{\"a\":\"x\xc3\xa9\",\"b\":[1,2,{\"z\":null}],\"n\":-125.0}") == 0);
    free(s);
    s = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    report("dump_ascii", s && strstr(s, "x\\u00E9") != NULL);
    free(s);
    json_decref(root);
  }
  json_t *bad = json_loads("{\"a\": [1, 2,}", 0, &err);
  report("reject_malformed", bad == NULL && err.line == 1);
  printf("SUMMARY pass=%d fail=%d\n", pass, fail);
  return fail != 0;
}
