// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_json.h"

#include <functional>
#include <stdexcept>
#include <string>

namespace {

bool refuses(const std::function<void()>& operation)
{
    try {
        operation();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

} // namespace

int main()
{
    const std::string source =
        " { \"z\" : [true,null,7,\"line\\n\"], \"a\" : {\"unicode\":\"\\ud83d\\ude80\"} } ";
    const usk::json::Value parsed = usk::json::parse(source);
    const std::string expected =
        "{\"a\":{\"unicode\":\"\xf0\x9f\x9a\x80\"},\"z\":[true,null,7,\"line\\n\"]}";
    if (usk::json::canonical(parsed) != expected ||
        parsed.at("z").as_array().at(2).as_unsigned() != 7) {
        return 1;
    }
    if (!refuses([] { (void)usk::json::parse("{\"a\":1,\"a\":2}"); }) ||
        !refuses([] { (void)usk::json::parse("01"); }) ||
        !refuses([] { (void)usk::json::parse("1.0"); }) ||
        !refuses([] { (void)usk::json::parse("-1"); }) ||
        !refuses([] { (void)usk::json::parse("\"\\ud800\""); }) ||
        !refuses([] { (void)usk::json::parse(std::string("\"") + "\xc0\xaf" + "\""); }) ||
        !refuses([] { (void)usk::json::parse("{} trailing"); })) {
        return 2;
    }
    usk::json::ParseLimits limits;
    limits.max_values = 2;
    if (!refuses([&] { (void)usk::json::parse("[1,2]", limits); })) return 3;
    return usk::json::sha256_canonical(usk::json::parse("{}")) ==
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" ? 0 : 4;
}
