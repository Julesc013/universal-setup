// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_consumer_access.h"
#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"
#include "usk_publisher_security_descriptor.h"
#include <aclapi.h>
#include <memory>
#include <map>
#include <stdexcept>
namespace usk::platform::windows {
namespace {
struct CloseHandleDeleter {
    void operator()(void* value) const { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
}
std::size_t grant_publisher_consumer_read(HANDLE visible,
    const PublisherTreeObservation& verified, const std::string& service_sid,
    const std::string& consumer_sid, HANDLE stop_event,
    const std::function<void(std::size_t)>& after_grant) {
    const auto expected = publisher_consumer_read_projection(verified, service_sid, consumer_sid);
    require_publisher_tree_phase_match(expected, publisher_consumer_read_projection(
        observe_publisher_tree(visible), service_sid, consumer_sid));
    const auto descriptor = make_publisher_consumer_security_descriptor(
        std::wstring(service_sid.begin(), service_sid.end()), consumer_sid);
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(const_cast<unsigned char*>(descriptor.data()),
            &present, &dacl, &defaulted) || !present || !dacl) {
        throw std::runtime_error("consumer descriptor has no explicit DACL");
    }
    std::size_t changed = 0, visited = 0;
    std::map<std::string, std::wstring> identities;
    identities.emplace(expected.root.file_id, expected.root.native_name);
    for (const auto& entry : expected.descendants) {
        if (!identities.emplace(entry.object.file_id, entry.object.native_name).second) {
            throw std::runtime_error("consumer closure has aliased identities");
        }
    }
    const auto cancelled = [&] {
        if (stop_event && WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) {
            throw std::runtime_error("consumer access interrupted; replay required");
        }
    };
    std::function<void(HANDLE,bool,std::size_t)> grant;
    grant = [&](HANDLE object, bool directory, std::size_t depth) {
        cancelled();
        if (depth > 64 || ++visited > expected.descendants.size() + 1) {
            throw std::runtime_error("consumer access traversal exceeds verified closure");
        }
        if (directory) {
            for (const auto& entry : observe_publisher_directory_entries(object)) {
                std::unique_ptr<void, CloseHandleDeleter> child(open_publisher_listed_child(
                    object, entry, false, false, false, true));
                grant(child.get(), (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0, depth + 1);
            }
        }
        cancelled();
        const auto before = directory ? observe_publisher_directory_handle(object) :
            observe_publisher_file_handle(object);
        const auto bound = identities.find(before.file_id);
        if (bound == identities.end() || bound->second != before.native_name) {
            throw std::runtime_error("consumer access object escaped verified closure");
        }
        PublisherTreeObservation single{};
        single.root = before;
        (void)publisher_consumer_read_projection(single, service_sid, consumer_sid);
        if (before.dacl_aces.size() == 2) {
            const DWORD error = SetSecurityInfo(object, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, dacl, nullptr);
            if (error != ERROR_SUCCESS) {
                throw std::runtime_error("consumer read DACL update failed; Win32 " + std::to_string(error));
            }
            ++changed;
            if (after_grant) after_grant(changed);
        }
        const auto after = directory ? observe_publisher_directory_handle(object) :
            observe_publisher_file_handle(object);
        single.root = after;
        (void)publisher_consumer_read_projection(single, service_sid, consumer_sid, true);
        if (before.file_id != after.file_id || before.native_name != after.native_name) {
            throw std::runtime_error("consumer access object identity changed");
        }
    };
    grant(visible, true, 0);
    cancelled();
    if (visited != expected.descendants.size() + 1) {
        throw std::runtime_error("consumer access visited closure differs");
    }
    require_publisher_tree_phase_match(expected, publisher_consumer_read_projection(
        observe_publisher_tree(visible), service_sid, consumer_sid, true));
    return visited;
}
}
#endif
