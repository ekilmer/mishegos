#include "../worker.h"
#include <stdio.h>

extern void worker_ctor();
extern void try_decode(decode_result *result, uint8_t *raw_insn, uint8_t length);

int main() {
  worker_ctor();
  decode_result result;
  uint8_t insn[] = {0xf0, 0x67, 0xff, 0x00};
  uint8_t insn2[] = {0x48, 0x89, 0xF8};
  uint8_t insn3[] = {0x48, 0x81, 0xec, 0xc0, 0x0f, 0x00, 0x00};

  try_decode(&result, insn, sizeof(insn));
  if (result.status == S_SUCCESS) {
    printf("%s", result.result);
  } else {
    printf("ERROR\n");
  }

  try_decode(&result, insn2, sizeof(insn2));
  if (result.status == S_SUCCESS) {
    printf("%s", result.result);
  } else {
    printf("ERROR\n");
  }

  try_decode(&result, insn3, sizeof(insn3));
  if (result.status == S_SUCCESS) {
    printf("%s", result.result);
  } else {
    printf("ERROR\n");
  }
}
