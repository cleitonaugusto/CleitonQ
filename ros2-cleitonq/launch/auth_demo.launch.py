"""
CleitonQ ROS2 demo launch — parallel-topic authentication.

Starts:
  - auth_gcs_node:   publishes /cleitonq/cmd + /cleitonq/cmd/auth
  - auth_drone_node: verifies auth, publishes /cleitonq/cmd/verified

Usage:
  colcon build --packages-select cleitonq_ros2
  source install/setup.bash
  ros2 launch cleitonq_ros2 auth_demo.launch.py

Monitor topics:
  ros2 topic echo /cleitonq/cmd
  ros2 topic echo /cleitonq/cmd/auth
  ros2 topic echo /cleitonq/cmd/verified

Reference: https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/
"""

from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    gcs_node = Node(
        package="cleitonq_ros2",
        executable="auth_gcs_node",
        name="cleitonq_gcs",
        output="screen",
        parameters=[{
            # In production: load session_key from KEM handshake result
            "demo_mode": True,
        }],
    )

    drone_node = Node(
        package="cleitonq_ros2",
        executable="auth_drone_node",
        name="cleitonq_drone",
        output="screen",
        parameters=[{
            "demo_mode": True,
        }],
    )

    return LaunchDescription([gcs_node, drone_node])
