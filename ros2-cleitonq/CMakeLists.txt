cmake_minimum_required(VERSION 3.20)
project(cleitonq_ros2 VERSION 0.2.0)

# ── ROS2 Humble dependencies ──────────────────────────────────────────────────

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(rosidl_default_generators REQUIRED)

# ── CleitonQ C API ────────────────────────────────────────────────────────────
# Build from the sibling capi/ directory inside the CleitonQ repo.
# For installed deployments, use find_package(CleitonQ REQUIRED) instead.

set(CLEITONQ_CAPI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../capi")

if(EXISTS "${CLEITONQ_CAPI_DIR}/CMakeLists.txt")
    add_subdirectory("${CLEITONQ_CAPI_DIR}" cleitonq_capi_build)
else()
    # Fallback: expect CleitonQ to be installed system-wide
    find_package(CleitonQ REQUIRED)
endif()

# ── Message generation ────────────────────────────────────────────────────────

rosidl_generate_interfaces(${PROJECT_NAME}
    "msg/AuthTag.msg"
    "msg/DsaSignature.msg"
    DEPENDENCIES std_msgs
)

# ── Nodes ─────────────────────────────────────────────────────────────────────

# Ground station node (publishes cmd + auth sidecar)
add_executable(auth_gcs_node src/auth_gcs_node.cpp)
target_include_directories(auth_gcs_node PRIVATE
    include
    "${CLEITONQ_CAPI_DIR}/include"
)
target_link_libraries(auth_gcs_node PRIVATE CleitonQ::capi)
ament_target_dependencies(auth_gcs_node rclcpp std_msgs)
rosidl_get_typesupport_target(cpp_typesupport_target ${PROJECT_NAME} "rosidl_typesupport_cpp")
target_link_libraries(auth_gcs_node PRIVATE "${cpp_typesupport_target}")

# Drone/robot node (verifies auth before acting on commands)
add_executable(auth_drone_node src/auth_drone_node.cpp)
target_include_directories(auth_drone_node PRIVATE
    include
    "${CLEITONQ_CAPI_DIR}/include"
)
target_link_libraries(auth_drone_node PRIVATE CleitonQ::capi)
ament_target_dependencies(auth_drone_node rclcpp std_msgs)
target_link_libraries(auth_drone_node PRIVATE "${cpp_typesupport_target}")

# ── Install ───────────────────────────────────────────────────────────────────

install(TARGETS auth_gcs_node auth_drone_node
    DESTINATION lib/${PROJECT_NAME}
)

install(DIRECTORY include/
    DESTINATION include
)

install(DIRECTORY launch/
    DESTINATION share/${PROJECT_NAME}/launch
)

# ── Tests ─────────────────────────────────────────────────────────────────────

if(BUILD_TESTING)
    find_package(ament_lint_auto REQUIRED)
    ament_lint_auto_find_test_dependencies()
endif()

ament_package()
