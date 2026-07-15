cmake_minimum_required(VERSION 3.16)

project(libsigner_compat LANGUAGES CXX)

find_package(Threads REQUIRED)

option(LIBSIGNER_COMPAT_BUILD_JNI
       "Build the JNI compatibility shared library" ON)
option(LIBSIGNER_COMPAT_BUILD_TESTS
       "Build non-sensitive host tests" ON)

if((LIBSIGNER_COMPAT_BUILD_JNI OR LIBSIGNER_COMPAT_BUILD_TESTS)
        AND NOT ANDROID)
    find_package(JNI REQUIRED)
endif()

add_library(signer_compat_core STATIC
    src/signer_backend.cpp
)
target_include_directories(signer_compat_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(signer_compat_core PUBLIC cxx_std_17)
target_compile_options(signer_compat_core PRIVATE
    -Wall -Wextra -Werror
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)
set_target_properties(signer_compat_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)
if(CMAKE_DL_LIBS)
    target_link_libraries(signer_compat_core PUBLIC ${CMAKE_DL_LIBS})
endif()
target_link_libraries(signer_compat_core PUBLIC Threads::Threads)

if(LIBSIGNER_COMPAT_BUILD_JNI)
    add_library(signer_compat SHARED
        src/signer_jni_bridge.cpp
    )
    target_include_directories(signer_compat PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${JNI_INCLUDE_DIRS}
    )
    target_link_libraries(signer_compat PRIVATE signer_compat_core)
    if(UNIX AND NOT APPLE)
        target_link_options(signer_compat PRIVATE -Wl,--exclude-libs,ALL)
    endif()
    target_compile_features(signer_compat PRIVATE cxx_std_17)
    target_compile_options(signer_compat PRIVATE
        -Wall -Wextra -Werror
        -fvisibility=hidden
        -fvisibility-inlines-hidden
    )
    set_target_properties(signer_compat PROPERTIES
        OUTPUT_NAME signer_compat
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
endif()

if(LIBSIGNER_COMPAT_BUILD_TESTS)
    enable_testing()

    add_executable(signer_backend_test
        src/fake_signer_backend.cpp
        tests/signer_backend_test.cpp
    )
    target_include_directories(signer_backend_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(signer_backend_test PRIVATE signer_compat_core)
    target_compile_features(signer_backend_test PRIVATE cxx_std_17)
    target_compile_options(signer_backend_test PRIVATE
        -Wall -Wextra -Werror
    )
    add_test(NAME signer_backend_test COMMAND signer_backend_test)

    add_executable(signer_bridge_config_test
        src/signer_jni_bridge.cpp
        src/fake_signer_backend.cpp
        tests/signer_bridge_config_test.cpp
    )
    target_include_directories(signer_bridge_config_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${JNI_INCLUDE_DIRS}
    )
    target_link_libraries(signer_bridge_config_test PRIVATE signer_compat_core)
    target_compile_definitions(signer_bridge_config_test PRIVATE
        LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND
    )
    target_compile_features(signer_bridge_config_test PRIVATE cxx_std_17)
    target_compile_options(signer_bridge_config_test PRIVATE
        -Wall -Wextra -Werror
    )
    add_test(NAME signer_bridge_config_test COMMAND signer_bridge_config_test)

    add_executable(signer_bridge_production_config_test
        src/signer_jni_bridge.cpp
        tests/signer_bridge_production_config_test.cpp
    )
    target_include_directories(signer_bridge_production_config_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${JNI_INCLUDE_DIRS}
    )
    target_link_libraries(
        signer_bridge_production_config_test PRIVATE signer_compat_core)
    target_compile_features(
        signer_bridge_production_config_test PRIVATE cxx_std_17)
    target_compile_options(signer_bridge_production_config_test PRIVATE
        -Wall -Wextra -Werror
    )
    add_test(
        NAME signer_bridge_production_config_test
        COMMAND signer_bridge_production_config_test)
endif()
