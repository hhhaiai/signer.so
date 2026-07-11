#include "trace_schema.h"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>

int main() {
  using libsigner::trace::TraceEvent;

  TraceEvent event;
  event.backend = "qbdi";
  event.module = "lib\"signer.so";
  event.module_base = 0x70000000;
  event.module_size = 0x120000;
  event.pc = 0x700a95ac;
  event.instruction_size = 4;
  event.mnemonic = "bl";
  event.disassembly = "bl 0x8b510\n";
  event.thread_id = 7;
  event.sequence = 42;

  assert(event.relative_pc() == 0xa95ac);
  assert(event.in_module(0x70000000, 0x70100000));

  const std::string expected =
      "{\"schema\":\"libsigner.trace/v1\",\"backend\":\"qbdi\","
      "\"event\":\"instruction\",\"module\":\"lib\\\"signer.so\","
      "\"module_base\":\"0x70000000\",\"module_size\":\"0x120000\","
      "\"pc\":\"0x700a95ac\","
      "\"relative_pc\":\"0xa95ac\",\"instruction_size\":4,"
      "\"mnemonic\":\"bl\",\"disassembly\":\"bl 0x8b510\\n\","
      "\"thread_id\":7,\"sequence\":42}";
  assert(libsigner::trace::to_json_line(event) == expected);

  TraceEvent invalid = event;
  invalid.pc = invalid.module_base - 1;
  bool threw = false;
  try {
    (void)invalid.relative_pc();
  } catch (const std::out_of_range &) {
    threw = true;
  }
  assert(threw);

  return 0;
}
