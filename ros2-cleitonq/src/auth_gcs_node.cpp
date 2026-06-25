// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. MIT OR Apache-2.0.
//
// Ground Control Station node — signs ROS2 commands with HMAC-SHA3-256
// and publishes authentication material on a parallel sidecar topic.
//
// Pattern: parallel-topic authentication (IETF draft-bezerra-relay-auth-transparency)
//
// Publish:
//   /cleitonq/cmd          std_msgs/String  — plaintext command (relay carries this)
//   /cleitonq/cmd/auth     AuthTag          — HMAC auth (relay must NOT discard this)
//
// The drone node subscribes to both topics and verifies auth before acting.

#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <cleitonq_ros2/msg/auth_tag.hpp>
#include <cleitonq_ros2/channel_auth.hpp>
#include <atomic>
#include <cstring>

class AuthGcsNode : public rclcpp::Node {
public:
    AuthGcsNode() : Node("cleitonq_gcs"), nonce_(0) {
        // In production: session_key comes from ML-KEM handshake with the drone.
        // Here we use a fixed demo key. Replace with KEM output in deployment.
        std::array<uint8_t, 32> session_key{};
        session_key.fill(0xAB); // DEMO ONLY — use cleitonq_kem_encapsulate() in production

        channel_ = std::make_unique<cleitonq_ros2::AuthChannel>(
            session_key.data(), CLEITONQ_DOMAIN_C2);

        cmd_pub_ = create_publisher<std_msgs::msg::String>("/cleitonq/cmd", 10);
        auth_pub_ = create_publisher<cleitonq_ros2::msg::AuthTag>("/cleitonq/cmd/auth", 10);

        // Publish a command every 2 seconds for demo purposes.
        timer_ = create_wall_timer(std::chrono::seconds(2),
                                   [this]() { publish_command("ARM_DISARM arm=1 force=0"); });

        RCLCPP_INFO(get_logger(), "CleitonQ GCS node ready (parallel-topic auth)");
        RCLCPP_INFO(get_logger(), "  command topic: /cleitonq/cmd");
        RCLCPP_INFO(get_logger(), "  auth topic:    /cleitonq/cmd/auth");
    }

private:
    void publish_command(const std::string &cmd) {
        uint64_t nonce = ++nonce_;
        uint64_t seq_id = nonce;

        // Serialize the command bytes
        std::vector<uint8_t> payload(cmd.begin(), cmd.end());

        // Sign with HMAC-SHA3-256
        std::vector<uint8_t> packet = channel_->sign(payload, nonce);

        // Extract the 32-byte HMAC tag (last 32 bytes of the signed packet)
        // Wire format: [payload | nonce_le64 (8B) | HMAC-SHA3-256 (32B)]
        cleitonq_ros2::msg::AuthTag auth_msg;
        auth_msg.sequence_id = seq_id;
        auth_msg.nonce = nonce;
        std::copy(packet.end() - 32, packet.end(), auth_msg.hmac_tag.begin());

        // Publish command (relay will carry this)
        std_msgs::msg::String cmd_msg;
        cmd_msg.data = cmd;
        cmd_pub_->publish(cmd_msg);

        // Publish auth on parallel sidecar topic
        // A relay that forwards /cleitonq/cmd must also forward /cleitonq/cmd/auth
        // or the drone will reject the command — relay-transparent by design.
        auth_pub_->publish(auth_msg);

        RCLCPP_INFO(get_logger(), "Published: \"%s\" (nonce=%lu, seq=%lu)",
                    cmd.c_str(), nonce, seq_id);
    }

    std::unique_ptr<cleitonq_ros2::AuthChannel> channel_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr cmd_pub_;
    rclcpp::Publisher<cleitonq_ros2::msg::AuthTag>::SharedPtr auth_pub_;
    rclcpp::TimerBase::SharedPtr timer_;
    std::atomic<uint64_t> nonce_;
};

int main(int argc, char *argv[]) {
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<AuthGcsNode>());
    rclcpp::shutdown();
    return 0;
}
