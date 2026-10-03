// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_EFFECT_DISPATCH_H
#define USK_EFFECT_DISPATCH_H
#include <stdexcept>
namespace usk::base {
// Only the concrete transport may report this before it has sent effect
// request bytes. After dispatch, errors must preserve an unknown outcome.
class EffectRequestNotDispatched final : public std::runtime_error {
public:
    EffectRequestNotDispatched() : std::runtime_error("effect request was not dispatched") {}
};
}
#endif
