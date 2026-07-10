cmake_minimum_required(VERSION 3.16)
project(libsigner_qbdi_trace LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(trace_schema_test tests/trace_schema_test.cpp)
target_include_directories(trace_schema_test PRIVATE src)

enable_testing()
add_test(NAME trace_schema_test COMMAND trace_schema_test)

find_package(QBDI CONFIG QUIET)
add_library(android_attach_tracer SHARED src/android_attach_tracer.cpp)
target_include_directories(android_attach_tracer PRIVATE src)

if(QBDI_FOUND)
  target_compile_definitions(android_attach_tracer PRIVATE LIBSIGNER_HAVE_QBDI=1)
  if(TARGET QBDI::QBDI)
    target_link_libraries(android_attach_tracer PRIVATE QBDI::QBDI)
  elseif(TARGET QBDI)
    target_link_libraries(android_attach_tracer PRIVATE QBDI)
  else()
    message(FATAL_ERROR "QBDI was found but exported no QBDI target")
  endif()
else()
  message(STATUS "QBDI not found: building the explicit unavailable-backend stub")
endif()

