// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_publisher_metadata_parent_internal.h"
#if defined(_WIN32)
#include "usk_publisher_directory_entries.h"
#include <stdexcept>
#include <utility>

namespace usk::platform::windows::detail {
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
class QueryHandle final {
public:
    explicit QueryHandle(HANDLE value) : value_(value) {}
    ~QueryHandle() { if (value_) CloseHandle(value_); }
    QueryHandle(const QueryHandle&) = delete;
    QueryHandle& operator=(const QueryHandle&) = delete;
    HANDLE get() const { return value_; }
    void close() {
        const auto value = value_;
        value_ = nullptr; // A failed close is never retried.
        require(value && CloseHandle(value) != FALSE,
            "metadata parent query closure is unknown");
    }
private:
    HANDLE value_;
};
void match(HANDLE handle, const PublisherHandleObservation& expected,
    std::uint32_t granted_access) {
    require(equal_publisher_handle_observations(observe_publisher_directory_handle(handle), expected) &&
        observe_publisher_handle_granted_access(handle) == granted_access,
        "metadata retained parent identity, security or capability changed");
}
}
MetadataParentRead::MetadataParentRead(HANDLE root, PublisherHandleObservation expected_root,
    std::uint32_t root_access, std::vector<MetadataParentComponent> components)
    : root_(root), root_expected_(std::move(expected_root)), root_access_(root_access),
      components_(std::move(components)) {
    require(root_ && root_ != INVALID_HANDLE_VALUE && !components_.empty() &&
        components_.size() <= maximum_components, "metadata parent read exceeds its fixed topology");
    auto expected_name = root_expected_.native_name;
    for (const auto& component : components_) {
        require(is_publisher_canonical_component(component.name) &&
            component.handle && component.handle != INVALID_HANDLE_VALUE,
            "metadata parent read has an invalid fixed component");
        expected_name += L"\\" + component.name;
        require(component.expected.native_name == expected_name,
            "metadata parent read lacks its exact ordered namespace");
    }
}
void MetadataParentRead::require_current() const {
    require(!failed_.load() && process_ == GetCurrentProcessId() && thread_ == GetCurrentThreadId(),
        "metadata parent read failed or changed its original owner");
}
HANDLE MetadataParentRead::observe() const {
    try {
        require_current();
        match(root_, root_expected_, root_access_);
        HANDLE parent = root_;
        const PublisherHandleObservation* parent_expected = &root_expected_;
        for (const auto& component : components_) {
            require_current();
            match(component.handle, component.expected, component.granted_access);
            bool found = false;
            for (const auto& entry : observe_publisher_directory_entries(parent)) {
                if (CompareStringOrdinal(entry.name.c_str(), -1, component.name.c_str(), -1, TRUE) != CSTR_EQUAL)
                    continue;
                require(!found && entry.name == component.name,
                    "metadata retained parent has an ambiguous namespace");
                QueryHandle independent(open_publisher_listed_child(parent, entry));
                require(equal_publisher_handle_observations(
                    observe_publisher_directory_handle(independent.get()), component.expected),
                    "metadata retained parent no longer names the admitted object");
                independent.close();
                found = true;
            }
            require(found, "metadata retained parent disappeared");
            require(equal_publisher_handle_observations(
                observe_publisher_directory_handle(parent), *parent_expected),
                "metadata retained ancestor changed during its child query");
            parent = component.handle;
            parent_expected = &component.expected;
        }
        // No saved listing supplies completion. Fresh held facts close the
        // complete chain after all independent query-only reopens have closed.
        match(root_, root_expected_, root_access_);
        for (const auto& component : components_)
            match(component.handle, component.expected, component.granted_access);
        require_current();
        return components_.back().handle;
    } catch (...) { failed_.store(true); throw; }
}
} // namespace usk::platform::windows::detail
#endif
