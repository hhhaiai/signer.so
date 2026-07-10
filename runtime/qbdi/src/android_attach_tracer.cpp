#include "trace_schema.h"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#if defined(LIBSIGNER_HAVE_QBDI)
#include <QBDI.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

struct TraceContext {
  std::ofstream output;
  std::uint64_t module_base;
  std::uint64_t module_end;
  std::uint64_t max_events;
  std::uint64_t sequence = 0;
};

std::uint64_t current_thread_id() {
#if defined(__linux__) || defined(__ANDROID__)
  return static_cast<std::uint64_t>(::syscall(SYS_gettid));
#else
  return 0;
#endif
}

QBDI::VMAction on_instruction(QBDI::VMInstanceRef vm, QBDI::GPRState *,
                              QBDI::FPRState *, void *opaque) {
  auto &context = *static_cast<TraceContext *>(opaque);
  const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
      QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY);
  if (analysis == nullptr || analysis->address < context.module_base ||
      analysis->address >= context.module_end) {
    return QBDI::CONTINUE;
  }
  if (context.sequence >= context.max_events) {
    return QBDI::STOP;
  }

  libsigner::trace::TraceEvent event;
  event.backend = "qbdi";
  event.module = "libsigner.so";
  event.module_base = context.module_base;
  event.module_size = context.module_end - context.module_base;
  event.pc = analysis->address;
  event.instruction_size = analysis->instSize;
  event.mnemonic = analysis->mnemonic == nullptr ? "" : analysis->mnemonic;
  event.disassembly =
      analysis->disassembly == nullptr ? "" : analysis->disassembly;
  event.thread_id = current_thread_id();
  event.sequence = context.sequence++;
  context.output << libsigner::trace::to_json_line(event) << '\n';
  return context.output.good() ? QBDI::CONTINUE : QBDI::STOP;
}

} // namespace

// Call this from an injected/in-process Android or Linux x86_64 harness. It is
// not an arbitrary remote-PID attach API and it does not make Android ELF
// loadable on macOS. The caller must provide a valid entry/stop range and any
// required register/stack state through its surrounding QBDI harness.
extern "C" int libsigner_qbdi_trace(std::uintptr_t start, std::uintptr_t stop,
                                    std::uintptr_t module_base,
                                    std::size_t module_size,
                                    const char *output_path,
                                    std::uint64_t max_events) {
  if (start == 0 || stop <= start || module_size == 0 || output_path == nullptr ||
      max_events == 0) {
    return 64;
  }
  TraceContext context{{output_path, std::ios::out | std::ios::trunc}, module_base,
                       module_base + module_size, max_events};
  if (!context.output) {
    return 73;
  }

  QBDI::VM vm;
  if (!vm.addInstrumentedRange(start, stop)) {
    return 78;
  }
  vm.addCodeCB(QBDI::PREINST, on_instruction, &context);
  const bool completed = vm.run(start, stop);
  context.output.flush();
  return completed && context.output.good() ? 0 : 70;
}

#else

extern "C" int libsigner_qbdi_trace(std::uintptr_t, std::uintptr_t,
                                    std::uintptr_t, std::size_t, const char *,
                                    std::uint64_t) {
  std::fputs("QBDI support was not compiled; run check-environment.sh.\n", stderr);
  return 78;
}

#endif
