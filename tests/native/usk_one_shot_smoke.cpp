// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_one_shot.h"
#include "usk_json.h"

#include <cstdint>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

class BadAtEndBuffer final : public std::streambuf {
public:
    explicit BadAtEndBuffer(std::string bytes) : bytes_(std::move(bytes))
    {
        setg(bytes_.data(), bytes_.data(), bytes_.data() + bytes_.size());
    }
    void mark_bad_and_eof_on_end(std::istream& input) { owner_ = &input; }

protected:
    int_type underflow() override
    {
        if (gptr() != egptr()) return traits_type::to_int_type(*gptr());
        if (owner_ != nullptr) {
            owner_->setstate(std::ios::badbit | std::ios::eofbit);
            return traits_type::eof();
        }
        throw std::ios_base::failure("injected read failure");
    }

private:
    std::string bytes_;
    std::istream* owner_ = nullptr;
};

class FailOnFlushBuffer final : public std::stringbuf {
protected:
    int sync() override { return -1; }
};

bool refused_with(const std::string& request, const std::string& code)
{
    const auto result = usk::command::run_one_shot(request);
    if (result.exit_code == 0 || result.document.find("SECRET_CANARY") != std::string::npos ||
        result.diagnostic.find("SECRET_CANARY") != std::string::npos) return false;
    const auto parsed = usk::json::parse(result.document);
    return parsed.at("status").as_string() == "refused" &&
        parsed.at("error").at("code").as_string() == code;
}

bool frame_refused(const std::string& source)
{
    std::istringstream input(source);
    try {
        (void)usk::command::read_bounded_request(input, true);
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

} // namespace

int main()
{
    const std::string request =
        "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"probe-1\","
        "\"command\":\"command_graph.inspect\",\"payload\":{},\"dry_run\":true}";
    const auto result = usk::command::run_one_shot(request);
    if (result.exit_code != 0 || !result.diagnostic.empty()) return 1;
    const auto parsed = usk::json::parse(result.document);
    if (parsed.at("request_id").as_string() != "probe-1" ||
        parsed.at("status").as_string() != "ok" ||
        parsed.at("result").type() != usk::json::Value::Type::object) return 2;

    if (!refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"schema\":\"SECRET_CANARY\"}",
            "invalid_request") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"install_local.apply\",\"payload\":{},\"dry_run\":true}",
            "command_unavailable") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"policy.inspect\",\"payload\":{},\"dry_run\":false}",
            "invalid_request") ||
        !refused_with(
            "{\"schema\":\"usk.oneshot_request.v1\",\"request_id\":\"x\","
            "\"command\":\"policy.inspect\",\"payload\":{\"a\":1,\"a\":2},"
            "\"dry_run\":true}", "invalid_request")) return 3;

    std::ostringstream frame;
    usk::command::write_result(frame, request, true);
    std::istringstream frame_input(frame.str());
    if (usk::command::read_bounded_request(frame_input, true) != request) return 4;
    if (!frame_refused(std::string("\x00\x10\x00\x01", 4)) ||
        !frame_refused(std::string("\x00\x00\x00\x05" "ab", 6)) ||
        !frame_refused(std::string("\x00\x00\x00\x02" "abx", 7))) return 5;

    std::istringstream oversized(std::string(usk::command::max_request_bytes + 1, 'x'));
    try {
        (void)usk::command::read_bounded_request(oversized, false);
        return 6;
    } catch (const std::runtime_error&) {
    }
    std::ostringstream plain;
    usk::command::write_result(plain, result.document, false);
    if (plain.str() != result.document + "\n") return 7;

    const std::string framed_request =
        std::string("\x00\x00\x00", 3) + static_cast<char>(request.size()) + request;
    BadAtEndBuffer bad_frame(framed_request);
    std::istream bad_frame_input(&bad_frame);
    try {
        (void)usk::command::read_bounded_request(bad_frame_input, true);
        return 8;
    } catch (const std::runtime_error&) {
    }
    BadAtEndBuffer bad_plain(request);
    std::istream bad_plain_input(&bad_plain);
    bad_plain.mark_bad_and_eof_on_end(bad_plain_input);
    try {
        (void)usk::command::read_bounded_request(bad_plain_input, false);
        return 9;
    } catch (const std::runtime_error&) {
    }
    FailOnFlushBuffer bad_output_buffer;
    std::ostream bad_output(&bad_output_buffer);
    try {
        usk::command::write_result(bad_output, result.document, false);
        return 10;
    } catch (const std::runtime_error&) {
    }
    return 0;
}
