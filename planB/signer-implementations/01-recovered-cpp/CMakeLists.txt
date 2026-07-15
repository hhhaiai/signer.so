cmake_minimum_required(VERSION 3.16)

project(recovered_primitives LANGUAGES CXX)

add_executable(recovered-primitives
    src/recovered_primitives.cpp
)

target_compile_features(recovered-primitives PRIVATE cxx_std_17)
set_target_properties(recovered-primitives PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_STANDARD_REQUIRED YES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}"
)

if(MSVC)
    target_compile_options(recovered-primitives PRIVATE /W4 /WX)
else()
    target_compile_options(recovered-primitives PRIVATE -Wall -Wextra -Werror)
endif()
