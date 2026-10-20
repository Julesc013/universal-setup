// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_product_install.h"
#include "usk_product_info.h"
#include "usk_json.h"
#include <algorithm>
#include <initializer_list>
#include <stdexcept>

namespace usk::command {
namespace {
using usk::json::Value;

void fields(const Value& value, std::initializer_list<const char*> names)
{
    if (value.as_object().size() != names.size())
        throw std::runtime_error("unexpected authored install field");
    for (const char* name : names)
        if (!value.contains(name)) throw std::runtime_error("missing authored install field");
}

Value parse(const std::string& text, std::size_t bound)
{
    usk::json::ParseLimits limits;
    limits.max_bytes = bound;
    limits.max_string_bytes = 512u * 1024u;
    limits.max_values = 300000;
    return usk::json::parse(text, limits);
}

void identifier(const Value& value)
{
    const auto& text = value.as_string();
    if (text.empty() || text.size() > 128 ||
        !std::all_of(text.begin(), text.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        })) throw std::runtime_error("invalid authored invocation identifier");
}

void timestamp(const Value& value)
{
    const auto& text = value.as_string();
    if (text.size() != 20 || text[4] != '-' || text[7] != '-' || text[10] != 'T' ||
        text[13] != ':' || text[16] != ':' || text[19] != 'Z')
        throw std::runtime_error("invalid authored application timestamp");
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) continue;
        if (text[i] < '0' || text[i] > '9') throw std::runtime_error("invalid authored application timestamp");
    }
}

const Value& successful_plan(const Value& response, const Value& request)
{
    fields(response, {"schema", "request_id", "status", "result", "error"});
    if (response.at("schema").as_string() != "usk.oneshot_response.v1" ||
        response.at("request_id").as_string() != request.at("request_id").as_string() ||
        response.at("status").as_string() != "ok" ||
        response.at("error").type() != Value::Type::null_value)
        throw std::runtime_error("review is not a successful plan");
    const auto& result = response.at("result");
    if (result.at("schema").as_string() != "usk.command_response.v1" ||
        result.at("status").as_string() != "ok")
        throw std::runtime_error("review is not a native plan");
    const auto& plan = result.at("payload");
    if (plan.at("schema").as_string() != "usk.install_plan.v1" ||
        plan.at("operation").as_string() != "install_local" ||
        plan.at("status").as_string() != "planned" ||
        plan.at("required_commit_authority").as_string() != "staged_child_bound_v1")
        throw std::runtime_error("review plan kind differs");
    return plan;
}
} // namespace

static OneShotResult plan_product_install_using(const std::filesystem::path& bundle,
    const std::string& options, const std::function<OneShotResult(const std::string&)>& planner)
{
    const auto request_text = compose_product_install_plan(bundle, options);
    const auto request = parse(request_text, max_request_bytes);
    auto response = planner(request_text);
    if (response.exit_code != 0) return response;
    const auto native = parse(response.document, max_response_bytes);
    (void)successful_plan(native, request);
    response.document = usk::json::canonical(Value(Value::Object{
        {"schema", Value("usk.authored_install_review.v1")},
        {"request", request}, {"response", native}}));
    if (response.document.size() > max_response_bytes)
        throw std::runtime_error("authored review exceeds response byte bound");
    return response;
}

static OneShotResult apply_product_install_using(const std::filesystem::path& bundle,
    const std::string& review_text, const std::string& confirmation_text,
    const std::function<OneShotResult(const std::string&)>& planner, const CandidateTransport& transport,
    bool registered_planning = false)
{
    const auto review = parse(review_text, max_response_bytes);
    fields(review, {"schema", "request", "response"});
    if (review.at("schema").as_string() != "usk.authored_install_review.v1")
        throw std::runtime_error("unsupported authored install review");
    const auto& original = review.at("request");
    const auto& payload = original.at("payload");
    const auto& entries = payload.at("recipe").at("entrypoints").as_array();
    if (entries.size() != 1) throw std::runtime_error("authored entrypoint count differs");
    const Value options(Value::Object{
        {"schema", Value("usk.authored_install_options.v1")},
        {"request_id", original.at("request_id")}, {"install_id", payload.at("install_id")},
        {"created_at", payload.at("created_at")}, {"target_root", payload.at("target").at("root")},
        {"entrypoint", entries.front()}});
    // This repeats the complete package verification, and admits only a request
    // that this fixed compositor can produce. No review-supplied extra controls.
    const auto fresh_request = compose_product_install_plan(bundle, usk::json::canonical(options));
    (void)parse(fresh_request, max_request_bytes);
    if (!usk::json::equal_values(original, parse(fresh_request, max_request_bytes)))
        throw std::runtime_error("review request differs from verified package");
    const auto& plan = successful_plan(review.at("response"), original);
    const auto confirmation = parse(confirmation_text, 16384);
    fields(confirmation, {"schema", "request_id", "reviewed_plan_id", "reviewed_plan_digest",
        "transaction_id", "applied_at", "confirmation"});
    if (confirmation.at("schema").as_string() != "usk.authored_install_confirmation.v1" ||
        confirmation.at("confirmation").as_string() != "APPLY" ||
        confirmation.at("reviewed_plan_id").as_string() != plan.at("plan_id").as_string() ||
        confirmation.at("reviewed_plan_digest").as_string() != plan.at("plan_digest").as_string())
        throw std::runtime_error("explicit reviewed plan confirmation differs");
    identifier(confirmation.at("request_id"));
    identifier(confirmation.at("transaction_id"));
    timestamp(confirmation.at("applied_at"));
    // Never infer a plan digest by hashing its public response: the lifecycle's
    // digest has a different projection. Re-plan read-only and compare ALL bytes
    // semantically, including policy, source, target, effects and planned files.
    const auto fresh_plan = planner(fresh_request);
    // A failed remote query has its own owned correlated result. Preserve it;
    // it is not an apply outcome, and it must never trigger effect dispatch.
    if (registered_planning && fresh_plan.exit_code != 0) return fresh_plan;
    if (fresh_plan.exit_code != 0 ||
        !usk::json::equal_values(parse(fresh_plan.document, max_response_bytes), review.at("response")))
        throw std::runtime_error("review is stale or differs from the native plan");
    const Value apply(Value::Object{
        {"schema", Value("usk.install_local_apply_request.v1")}, {"plan_request", payload},
        {"reviewed_plan_id", confirmation.at("reviewed_plan_id")},
        {"reviewed_plan_digest", confirmation.at("reviewed_plan_digest")},
        {"transaction_id", confirmation.at("transaction_id")}, {"applied_at", confirmation.at("applied_at")},
        {"confirmation", Value("APPLY")}});
    const auto request = usk::json::canonical(Value(Value::Object{
        {"schema", Value("usk.oneshot_request.v1")}, {"request_id", confirmation.at("request_id")},
        {"command", Value("install_local.apply")}, {"dry_run", Value(false)}, {"payload", apply}}));
    (void)parse(request, max_request_bytes);
    // The existing adapter prepares this invocation's UNKNOWN response before
    // dispatch; the registered publisher independently revalidates the plan.
    // No post-dispatch work here may reinterpret a transport failure as refusal.
    return run_publisher_one_shot(request, transport);
}

OneShotResult plan_product_install(const std::filesystem::path& bundle,
    const std::string& options, const OneShotContextConfig& context)
{
    return plan_product_install_using(bundle, options,
        [&](const std::string& request) { return run_one_shot(request, &context); });
}
OneShotResult plan_product_install(const std::filesystem::path& bundle,
    const std::string& options, const CandidateTransport& transport)
{
    return plan_product_install_using(bundle, options,
        [&](const std::string& request) { return run_publisher_one_shot(request, transport); });
}
OneShotResult apply_product_install(const std::filesystem::path& bundle,
    const std::string& review, const std::string& confirmation,
    const OneShotContextConfig& context, const CandidateTransport& transport)
{
    return apply_product_install_using(bundle, review, confirmation,
        [&](const std::string& request) { return run_one_shot(request, &context); }, transport);
}
OneShotResult apply_product_install_registered(const std::filesystem::path& bundle,
    const std::string& review, const std::string& confirmation, const CandidateTransport& transport)
{
    return apply_product_install_using(bundle, review, confirmation,
        [&](const std::string& request) { return run_publisher_one_shot(request, transport); }, transport, true);
}
} // namespace usk::command
