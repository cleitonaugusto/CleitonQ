// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. MIT OR Apache-2.0.
//
// Drone/robot node — verifies HMAC-SHA3-256 authentication from the
// parallel sidecar topic before acting on commands.
//
// If a DDS bridge or relay drops the auth topic (/cleitonq/cmd/auth),
// the drone rejects the command — relay-transparent by design.
// This is the fix for GHSA-f5rj-mrxh-r7vm.
//
// Subscribe:
//   /cleitonq/cmd          std_msgs/String  — command to verify
//   /cleitonq/cmd/auth     AuthTag          — HMAC auth material
//
// Publish:
//   /cleitonq/cmd/verified std_msgs/String  — verified and acted-on command

#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <cleitonq_ros2/msg/auth_tag.hpp>
#include <cleitonq_ros2/channel_auth.hpp>
#include <map>
#include <mutex>
#include <cstring>
#include <chrono>

static constexpr auto CORRELATION_TIMEOUT = std::chrono::seconds(5);

class AuthDroneNode : public rclcpp::Node {
public:
    AuthDroneNode() : Node("cleitonq_drone"), last_nonce_(0) {
        // Must use the same session key as the GCS.
        // In production: derived from ML-KEM decapsulation.
        std::array<uint8_t, 32> session_key{};
        session_key.fill(0xAB); // DEMO ONLY

        channel_ = std::make_unique<cleitonq_ros2::AuthChannel>(
            session_key.data(), CLEITONQ_DOMAIN_C2);

        cmd_sub_ = create_subscription<std_msgs::msg::String>(
            "/cleitonq/cmd", 10,
            [this](std_msgs::msg::String::SharedPtr msg) { on_command(msg); });

        auth_sub_ = create_subscription<cleitonq_ros2::msg::AuthTag>(
            "/cleitonq/cmd/auth", 10,
            [this](cleitonq_ros2::msg::AuthTag::SharedPtr msg) { on_auth(msg); });

        verified_pub_ = create_publisher<std_msgs::msg::String>(
            "/cleitonq/cmd/verified", 10);

        RCLCPP_INFO(get_logger(), "CleitonQ drone node ready");
        RCLCPP_INFO(get_logger(), "  Awaiting authenticated commands on /cleitonq/cmd");
        RCLCPP_WARN(get_logger(),
            "  Commands without matching /cleitonq/cmd/auth will be REJECTED");
    }

private:
    struct PendingCmd {
        std::string text;
        rclcpp::Time received_at;
    };

    struct PendingAuth {
        cleitonq_ros2::msg::AuthTag tag;
        rclcpp::Time received_at;
    };

    void on_command(std_msgs::msg::String::SharedPtr msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Buffer the command; wait for matching auth tag by sequence_id.
        // sequence_id is derived from position in stream — GCS publishes both atomically.
        uint64_t seq = ++cmd_counter_;
        pending_cmds_[seq] = {msg->data, now()};
        try_verify(seq);
    }

    void on_auth(cleitonq_ros2::msg::AuthTag::SharedPtr msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_auths_[msg->sequence_id] = {*msg, now()};
        try_verify(msg->sequence_id);
    }

    void try_verify(uint64_t seq) {
        auto cmd_it = pending_cmds_.find(seq);
        auto auth_it = pending_auths_.find(seq);
        if (cmd_it == pending_cmds_.end() || auth_it == pending_auths_.end())
            return;

        const auto &cmd_text = cmd_it->second.text;
        const auto &auth = auth_it->second.tag;

        // Reconstruct the signed wire packet to verify the HMAC.
        // Wire format: [payload | nonce_le64 (8B) | hmac_tag (32B)]
        std::vector<uint8_t> payload(cmd_text.begin(), cmd_text.end());
        std::vector<uint8_t> packet;
        packet.reserve(payload.size() + CLEITONQ_CHANNEL_OVERHEAD);
        packet.insert(packet.end(), payload.begin(), payload.end());

        // Append nonce as little-endian 8 bytes
        uint64_t nonce = auth.nonce;
        for (int i = 0; i < 8; ++i)
            packet.push_back(static_cast<uint8_t>(nonce >> (8 * i)));

        // Append HMAC tag
        packet.insert(packet.end(), auth.hmac_tag.begin(), auth.hmac_tag.end());

        auto result = channel_->verify(packet, last_nonce_);

        if (!result) {
            RCLCPP_ERROR(get_logger(),
                "AUTH FAILED for seq=%lu — command REJECTED: \"%s\"",
                seq, cmd_text.c_str());
        } else {
            last_nonce_ = result->nonce;
            RCLCPP_INFO(get_logger(),
                "AUTH OK seq=%lu nonce=%lu — executing: \"%s\"",
                seq, result->nonce, cmd_text.c_str());

            std_msgs::msg::String verified_msg;
            verified_msg.data = cmd_text;
            verified_pub_->publish(verified_msg);
        }

        pending_cmds_.erase(cmd_it);
        pending_auths_.erase(auth_it);
    }

    rclcpp::Time now() { return get_clock()->now(); }

    std::unique_ptr<cleitonq_ros2::AuthChannel> channel_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr cmd_sub_;
    rclcpp::Subscription<cleitonq_ros2::msg::AuthTag>::SharedPtr auth_sub_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr verified_pub_;
    std::mutex mutex_;
    std::map<uint64_t, PendingCmd> pending_cmds_;
    std::map<uint64_t, PendingAuth> pending_auths_;
    uint64_t cmd_counter_{0};
    uint64_t last_nonce_;
};

int main(int argc, char *argv[]) {
    rclcpp::init(argc, argv);
    rclcpp::spin(std::make_shared<AuthDroneNode>());
    rclcpp::shutdown();
    return 0;
}
