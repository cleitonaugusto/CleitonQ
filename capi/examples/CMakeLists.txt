cmake_minimum_required(VERSION 3.20)

# arm_disarm — full GCS→drone authentication flow
add_executable(arm_disarm arm_disarm.c)
target_link_libraries(arm_disarm PRIVATE CleitonQ::capi)
target_compile_options(arm_disarm PRIVATE -Wall -Wextra -Wpedantic)

# Run with: cmake --build build --target run_examples
add_custom_target(run_examples
    COMMAND arm_disarm
    DEPENDS arm_disarm
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Running CleitonQ C API examples..."
)
