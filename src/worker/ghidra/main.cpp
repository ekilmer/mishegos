#include "../worker.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <vector>

extern "C" void worker_ctor();
extern "C" void try_decode(decode_result *result, uint8_t *raw_insn, uint8_t length);

struct TestCaseInsn {
  std::vector<uint8_t> bytes;
  decode_status expected_status;
  std::string expected_disassembly;
};

static bool process_test_case(TestCaseInsn &test) {
  decode_result result{};
  try_decode(&result, test.bytes.data(), uint8_t(test.bytes.size()));

  // Remove newline at end of disassembly string
  std::string result_str(result.result);
  result_str.erase(std::remove(result_str.begin(), result_str.end(), '\n'), result_str.end());

  if (result.status != test.expected_status || test.expected_disassembly.compare(result_str) != 0) {
    std::cout << "ERROR: Expected status '" << status2str(test.expected_status) << "' and got '"
              << status2str(result.status) << "'\n";
    std::cout << "\tExpected disasm: '" << test.expected_disassembly << "' and got '" << result_str
              << "'\n";
    return false;
  }
  std::cout << "PASS: " << test.expected_disassembly << "\n";
  return true;
}

int main() {
  worker_ctor();

  std::vector<TestCaseInsn> insn_testing{
      // ----------- INC
      // Normal disassembly with LOCK valid instruction and register destination
      {{0xff, 0xc0}, S_SUCCESS, "INC EAX"},
      // INC.LOCK EAX not valid because it is not a memory destination
      {{0xf0, 0xff, 0xc0}, S_FAILURE, ""},

      // Normal disassembly with LOCK valid instruction and memory destination
      {{0xff, 0x00}, S_SUCCESS, "INC dword ptr [RAX]"},
      // INC.LOCK dword ptr [RAX] is valid because memory destination
      {{0xf0, 0xff, 0x00}, S_SUCCESS, "INC.LOCK dword ptr [RAX]"},

      // Normal disassembly with LOCK valid instruction and sized memory
      // destination
      {{0x66, 0xff, 0x00}, S_SUCCESS, "INC word ptr [RAX]"},
      // INC.LOCK word ptr [RAX] is valid because memory destination
      {{0xf0, 0x66, 0xff, 0x00}, S_SUCCESS, "INC.LOCK word ptr [RAX]"},
      // Move the prefix around
      {{0x66, 0xf0, 0xff, 0x00}, S_SUCCESS, "INC.LOCK word ptr [RAX]"},

      // Normal disassembly with LOCK valid instruction and sized memory
      // destination and sized register
      {{0x66, 0x67, 0xff, 0x00}, S_SUCCESS, "INC word ptr [EAX]"},
      // INC.LOCK word ptr [EAX] is valid because memory destination
      {{0xf0, 0x66, 0x67, 0xff, 0x00}, S_SUCCESS, "INC.LOCK word ptr [EAX]"},
      // Move the prefix around
      {{0x66, 0xf0, 0x67, 0xff, 0x00}, S_SUCCESS, "INC.LOCK word ptr [EAX]"},
      // Move the prefix around
      {{0x66, 0x67, 0xf0, 0xff, 0x00}, S_SUCCESS, "INC.LOCK word ptr [EAX]"},

      // ----------- XADD
      // Normal disassembly with LOCK valid instruction and register destination
      {{0x0f, 0xc1, 0xd8}, S_SUCCESS, "XADD EAX,EBX"},
      // XADD.LOCK EAX,EBX not valid because it is not a memory destination
      {{0xf0, 0x0f, 0xc1, 0xd8}, S_FAILURE, ""},

      // Normal disassembly with LOCK valid instruction and memory destination
      {{0x0f, 0xc1, 0x18}, S_SUCCESS, "XADD dword ptr [RAX],EBX"},
      // XADD.LOCK dword ptr [RAX],EBX is valid because memory destination
      {{0xf0, 0x0f, 0xc1, 0x18}, S_SUCCESS, "XADD.LOCK dword ptr [RAX],EBX"},

      // ----------- LOCK fails
      // Test normal invalid LOCK instruction
      {{0xB8, 0x01, 0x00, 0x00, 0x00}, S_SUCCESS, "MOV EAX,0x1"},
      // MOV.LOCK EAX, 0x1 is not valid because MOV can't have a LOCK prefix
      {{0xf0, 0xb8, 0x01, 0x00, 0x00, 0x00}, S_FAILURE, ""},

      // Test AVX invalid LOCK instruction
      {{0xc5, 0xf9, 0x6f, 0xc1}, S_SUCCESS, "VMOVDQA XMM0, XMM1"},
      // VMOVDQA.LOCK XMM0, XMM1 is not valid because MOV can't have a LOCK prefix
      {{0xf0, 0xc5, 0xf9, 0x6f, 0xc1}, S_FAILURE, ""},

      // ----------- No LOCK bit match
      // Test BMI2 RORX with 0xf0 in bit pattern
      {{0xc4, 0xe3, 0x7b, 0xf0, 0xc3, 0x02}, S_SUCCESS, "RORX EAX, EBX, 0x2"},
      // RORX.LOCK EAX, EBX, 0x2 Should fail with LOCK prefix still
      {{0xf0, 0xc4, 0xe3, 0x7b, 0xf0, 0xc3, 0x02}, S_FAILURE, ""},

      // ----------- XACQUIRE/XRELEASE prefix
      // Test XCHG because it has the most conditions
      // Test with register-only XCHG first
      {{0x87, 0xd9}, S_SUCCESS, "XCHG ECX,EBX"},
      // X-prefix does not cause a failure, just undefined/reserved behavior
      {{0xf2, 0x87, 0xd9}, S_SUCCESS, "XCHG ECX,EBX"}, // Current implementation fails
      {{0xf3, 0x87, 0xd9}, S_SUCCESS, "XCHG ECX,EBX"}, // Current implementation fails
      // LOCK prefix anywhere still causes failure though
      {{0xf0, 0x87, 0xd9}, S_FAILURE, ""},
      {{0xf2, 0xf0, 0x87, 0xd9}, S_FAILURE, ""},
      {{0xf0, 0xf2, 0x87, 0xd9}, S_FAILURE, ""},
      // Multiple X-prefix does not cause a failure, just undefined/reserved behavior
      {{0xf2, 0xf3, 0x87, 0xd9}, S_SUCCESS, "XCHG ECX,EBX"}, // Current implementation fails
      // Test with memory destination XCHG
      {{0x87, 0x19}, S_SUCCESS, "XCHG dword ptr [RCX],EBX"},
      {{0xf0, 0x87, 0x19}, S_SUCCESS, "XCHG.LOCK dword ptr [RCX],EBX"},
      // XCHG does not require a LOCK prefix to use XACQUIRE/XRELEASE
      {{0xf2, 0x87, 0x19}, S_SUCCESS, "XCHG.XACQUIRE dword ptr [RCX],EBX"},
      {{0xf3, 0x87, 0x19}, S_SUCCESS, "XCHG.XRELEASE dword ptr [RCX],EBX"},
      // ... but if LOCK appears, it should be noted, and prefix order does not matter
      {{0xf0, 0xf2, 0x87, 0x19}, S_SUCCESS, "XCHG.XACQUIRE.LOCK dword ptr [RCX],EBX"},
      {{0xf2, 0xf0, 0x87, 0x19}, S_SUCCESS, "XCHG.XACQUIRE.LOCK dword ptr [RCX],EBX"},
      {{0xf3, 0xf0, 0x87, 0x19}, S_SUCCESS, "XCHG.XRELEASE.LOCK dword ptr [RCX],EBX"},
      // Prefix order matters, and the last appearing prefix takes precedent
      {{0xf3, 0xf2, 0xf0, 0x87, 0x19}, S_SUCCESS, "XCHG.XACQUIRE.LOCK dword ptr [RCX],EBX"},
      {{0xf2, 0xf3, 0xf0, 0x87, 0x19}, S_SUCCESS, "XCHG.XRELEASE.LOCK dword ptr [RCX],EBX"},
  };

  return int(std::count_if(insn_testing.begin(), insn_testing.end(),
                           [](TestCaseInsn &test) { return !process_test_case(test); }));
}
