#ifndef LIBSIGNER_TRACE_SCHEMA_H
#define LIBSIGNER_TRACE_SCHEMA_H

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace libsigner::trace {

struct TraceEvent {
  std::string backend;
  std::string module;
  std::uint64_t module_base = 0;
  std::uint64_t module_size = 0;
  std::uint64_t pc = 0;
  std::uint32_t instruction_size = 0;
  std::string mnemonic;
  std::string disassembly;
  std::uint64_t thread_id = 0;
  std::uint64_t sequence = 0;

  std::uint64_t relative_pc() const {
    if (pc < module_base) {
      throw std::out_of_range("pc is below module base");
    }
    return pc - module_base;
  }

  bool in_module(std::uint64_t begin, std::uint64_t end) const {
    return begin <= pc && pc < end;
  }
};

inline std::string hex_address(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::nouppercase << value;
  return stream.str();
}

inline std::string escape_json(const std::string &value) {
  std::ostringstream stream;
  for (unsigned char character : value) {
    switch (character) {
    case '"':
      stream << "\\\"";
      break;
    case '\\':
      stream << "\\\\";
      break;
    case '\b':
      stream << "\\b";
      break;
    case '\f':
      stream << "\\f";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (character < 0x20) {
        stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
               << static_cast<unsigned int>(character) << std::dec;
      } else {
        stream << static_cast<char>(character);
      }
    }
  }
  return stream.str();
}

inline std::string to_json_line(const TraceEvent &event) {
  if (event.backend.empty() || event.module.empty()) {
    throw std::invalid_argument("backend and module are required");
  }
  if (event.instruction_size == 0) {
    throw std::invalid_argument("instruction_size must be positive");
  }
  if (event.module_size == 0 || event.relative_pc() >= event.module_size) {
    throw std::invalid_argument("pc must be inside a non-empty module");
  }

  std::ostringstream stream;
  stream << "{\"schema\":\"libsigner.trace/v1\","
         << "\"backend\":\"" << escape_json(event.backend) << "\","
         << "\"event\":\"instruction\","
         << "\"module\":\"" << escape_json(event.module) << "\","
         << "\"module_base\":\"" << hex_address(event.module_base) << "\","
         << "\"module_size\":\"" << hex_address(event.module_size) << "\","
         << "\"pc\":\"" << hex_address(event.pc) << "\","
         << "\"relative_pc\":\"" << hex_address(event.relative_pc()) << "\","
         << "\"instruction_size\":" << event.instruction_size << ','
         << "\"mnemonic\":\"" << escape_json(event.mnemonic) << "\","
         << "\"disassembly\":\"" << escape_json(event.disassembly) << "\","
         << "\"thread_id\":" << event.thread_id << ','
         << "\"sequence\":" << event.sequence << '}';
  return stream.str();
}

} // namespace libsigner::trace

#endif
