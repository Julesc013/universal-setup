// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#ifndef USK_PUBLISHER_CLIENT_CONTEXT_INTERNAL_H
#define USK_PUBLISHER_CLIENT_CONTEXT_INTERNAL_H
#include "usk_json.h"
#include <functional>
#include <string>

namespace usk::command::detail {
using PublisherClientTransport = std::function<std::string(const std::string&)>;
using PublisherClientPrepare = std::function<usk::json::Value(
    const std::string&, const usk::json::Value&)>;
struct PublisherClientResult { int status; const char* json; };

// Private adapter seam only. The public C factory always supplies the actual
// authenticated client and its fixed preparation. No callback is in the ABI.
// A context is externally serialized; independent contexts own separate buffers.
class PublisherClientContext final {
public:
    explicit PublisherClientContext(std::string endpoint);
    const std::string& endpoint() const noexcept { return endpoint_; }
    void clear() noexcept;
    PublisherClientResult execute(const char* command, const char* request, std::size_t size,
        const PublisherClientTransport& transport, const PublisherClientPrepare& prepare) noexcept;
private:
    std::string endpoint_, output_, unknown_;
};
}
#endif
