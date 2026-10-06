// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_consumer_access.h"
#include "usk_publisher_metadata.h"
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
PublisherHandleObservation grant_publisher_consumer_read_object(HANDLE object,
    bool directory, const PublisherHandleObservation& verified,
    const std::string& service_sid, const std::string& consumer_sid,
    const std::function<void()>& after_grant) {
    const auto observe = [&] { return directory ? observe_publisher_directory_handle(object) :
        observe_publisher_file_handle(object); };
    const auto before = observe();
    PublisherTreeObservation expected{}, actual{};
    expected.root = verified; actual.root = before;
    require_publisher_tree_phase_match(expected, actual);
    expected.root = publisher_consumer_read_object_projection(before, service_sid, consumer_sid);
    if (before.dacl_aces.size() == 2u) {
        const auto descriptor = make_publisher_consumer_security_descriptor(
            std::wstring(service_sid.begin(), service_sid.end()), consumer_sid);
        PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        if (!GetSecurityDescriptorDacl(const_cast<unsigned char*>(descriptor.data()),
                &present, &dacl, &defaulted) || !present || !dacl)
            throw std::runtime_error("consumer descriptor has no explicit DACL");
        require_current_publisher_effect_fence();
        const DWORD error = SetSecurityInfo(object, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr);
        if (error != ERROR_SUCCESS)
            throw std::runtime_error("consumer read DACL update failed; Win32 " + std::to_string(error));
        if (after_grant) after_grant();
    }
    const auto after = observe();
    actual.root = publisher_consumer_read_object_projection(after, service_sid, consumer_sid, true);
    require_publisher_tree_phase_match(expected, actual);
    return after;
}
std::size_t grant_publisher_consumer_read(HANDLE visible,
    const PublisherTreeObservation& verified, const std::string& service_sid,
    const std::string& consumer_sid, HANDLE stop_event,
    const std::function<void(std::size_t)>& after_grant) {
    const auto expected = publisher_consumer_read_projection(verified, service_sid, consumer_sid);
    require_publisher_tree_phase_match(expected, publisher_consumer_read_projection(
        observe_publisher_tree(visible), service_sid, consumer_sid));
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
        (void)grant_publisher_consumer_read_object(object, directory, before,
            service_sid, consumer_sid, [&] {
            ++changed;
            if (after_grant) after_grant(changed);
        });
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
