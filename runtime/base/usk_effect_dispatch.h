// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_EFFECT_DISPATCH_H
#define USK_EFFECT_DISPATCH_H
#include <stdexcept>
#include <string>
#include <utility>
namespace usk::base {
// Only the concrete transport may report this before it has sent effect
// request bytes. After dispatch, errors must preserve an unknown outcome.
class EffectRequestNotDispatched final : public std::runtime_error {
public:
    enum class Reason { admission_refused, operation_conflict, operation_cancelled };
    explicit EffectRequestNotDispatched(Reason reason = Reason::admission_refused,
        std::string inspection_reference = {}) :
        std::runtime_error("effect request was not dispatched"), reason_(reason),
        inspection_reference_(std::move(inspection_reference)) {}
    Reason reason() const noexcept { return reason_; }
    const std::string& inspection_reference() const noexcept { return inspection_reference_; }
private:
    Reason reason_;
    std::string inspection_reference_;
};
}
#endif
