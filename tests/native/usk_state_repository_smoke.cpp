// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_audit_repository.h"
#include "usk_state_repository.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

namespace {

struct Fixture {
    fs::path root;
    fs::path state;
    fs::path audit;

    explicit Fixture(const std::string& suffix)
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        root = fs::temp_directory_path() /
            ("usk-state-repository-" + suffix + "-" + std::to_string(nonce));
        state = root / "state";
        audit = root / "audit";
        fs::create_directories(state);
        fs::create_directories(audit);
    }

    ~Fixture()
    {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
};

bool refuses(const std::function<void()>& operation)
{
    try {
        operation();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

std::string read_text(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

usk::state::OwnershipManifest ownership(const fs::path& target)
{
    return usk::state::OwnershipManifest{
        "ownership.install.fixture",
        {},
        "install.fixture",
        target.string(),
        "tx.fixture",
        {
            {"app/readme.txt", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 6},
            {"app/bin/tool.exe", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 4},
        },
        {"app/bin", "app"}};
}

usk::state::InstalledState installed(const fs::path& target, const std::string& ownership_digest)
{
    usk::state::InstalledState result;
    result.install_id = "install.fixture";
    result.product_id = "product.fixture";
    result.product_version = "1.2.3";
    result.recipe_digest = "1111111111111111111111111111111111111111111111111111111111111111";
    result.source_archive_digest = "2222222222222222222222222222222222222222222222222222222222222222";
    result.target_root = target.string();
    result.component_selection = {"core"};
    result.ownership_manifest_ref = "ownership/ownership.install.fixture.json";
    result.ownership_manifest_digest = ownership_digest;
    result.entrypoints = {{"application", "app/bin/tool.exe", "application"}};
    result.setup_abi_major = 1;
    result.setup_abi_minor = 0;
    result.provider_revision = "fixture-provider-r1";
    result.transaction_id = "tx.fixture";
    result.created_at = "2026-07-14T00:00:00Z";
    result.last_verification = {
        "verify.fixture",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "pass",
        "2026-07-14T00:00:01Z"};
    result.audit_chain_id = "audit.fixture";
    result.lifecycle_status = "installed";
    return result;
}

usk::audit::AuditInput audit_input(const std::string& phase, const std::string& status)
{
    return usk::audit::AuditInput{
        "2026-07-14T00:00:02Z",
        "install_local",
        phase,
        status,
        "installation",
        "install.fixture",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "tx.fixture",
        "plan.fixture",
        "fixture event"};
}

} // namespace

int run()
{
    Fixture fixture("primary");
    usk::state::StateRepository state_repository(fixture.state);
    usk::audit::AuditRepository audit_repository(fixture.audit);
    if (!refuses([&] { (void)state_repository.read_installed("install.fixture"); }) ||
        fs::exists(fixture.state / "installed") || fs::exists(fixture.audit / "chains")) {
        return 1;
    }

    usk::state::StateRepository::initialize_layout(fixture.state);
    usk::audit::AuditRepository::initialize_layout(fixture.audit);
    audit_repository.initialize_chain("audit.fixture");

    auto incomplete_ownership = ownership(fixture.root / "invalid-target");
    incomplete_ownership.install_id = "install.invalid";
    incomplete_ownership.manifest_id = "ownership.install.invalid";
    incomplete_ownership.directories.clear();
    if (!refuses([&] { (void)state_repository.write_ownership(incomplete_ownership); }) ||
        fs::exists(fixture.state / "ownership/ownership.install.invalid.json")) {
        return 2;
    }
    const auto stored_ownership = state_repository.write_ownership(ownership(fixture.root / "target"));
    if (stored_ownership.files.front().relative_path != "app/bin/tool.exe" ||
        stored_ownership.manifest_digest.empty() ||
        state_repository.read_ownership("ownership.install.fixture").manifest_digest != stored_ownership.manifest_digest ||
        !refuses([&] { (void)state_repository.write_ownership(ownership(fixture.root / "target")); })) {
        return 3;
    }

    const auto state = installed(fixture.root / "target", stored_ownership.manifest_digest);
    state_repository.write_installed(state);
    const auto loaded = state_repository.read_installed("install.fixture");
    if (loaded.product_id != "product.fixture" || loaded.ownership_manifest_digest != stored_ownership.manifest_digest ||
        !refuses([&] { state_repository.write_installed(state); })) {
        return 4;
    }
    auto revised_state = state;
    revised_state.transaction_id = "tx.fixture.verify";
    revised_state.created_at = "2026-07-14T00:00:03Z";
    revised_state.lifecycle_status = "verified";
    state_repository.write_installed(revised_state);
    if (state_repository.read_installed("install.fixture").transaction_id != "tx.fixture.verify") {
        return 5;
    }

    const auto first = audit_repository.append("audit.fixture", audit_input("staging", "pass"));
    const auto second = audit_repository.append("audit.fixture", audit_input("completed", "pass"));
    const auto chain = audit_repository.read_and_validate_chain("audit.fixture");
    if (first.sequence != 0 || second.sequence != 1 || second.previous_event_digest != first.event_digest ||
        chain.size() != 2 || chain.back().event_digest != second.event_digest) {
        return 6;
    }

    Fixture mirror("mirror");
    usk::state::StateRepository::initialize_layout(mirror.state);
    usk::audit::AuditRepository::initialize_layout(mirror.audit);
    usk::state::StateRepository mirror_state(mirror.state);
    auto mirror_manifest = ownership(fixture.root / "target");
    const auto mirror_stored = mirror_state.write_ownership(mirror_manifest);
    if (mirror_stored.manifest_digest != stored_ownership.manifest_digest ||
        read_text(mirror.state / "ownership/ownership.install.fixture.json") !=
            read_text(fixture.state / "ownership/ownership.install.fixture.json")) {
        return 7;
    }

    {
        std::ofstream output(fixture.audit / "chains/audit.fixture/00000000000000000001.event.json",
                             std::ios::binary | std::ios::trunc);
        output << "{}";
    }
    if (!refuses([&] { (void)audit_repository.read_and_validate_chain("audit.fixture"); })) return 8;

    Fixture corpus("corpus");
    usk::state::StateRepository::initialize_layout(corpus.state);
    usk::audit::AuditRepository::initialize_layout(corpus.audit);
    usk::audit::AuditRepository corpus_audit(corpus.audit);
    corpus_audit.initialize_chain("audit.fixture");
    const fs::path corpus_source = fs::path(USK_SOURCE_DIR) / "tests/fixtures/setup/state-v1";
    fs::copy_file(corpus_source / "ownership.json", corpus.state / "ownership/install.fixture.json");
    fs::copy_file(corpus_source / "installed.json", corpus.state / "installed/install.fixture.json");
    fs::copy_file(corpus_source / "audit-event-0.json",
                  corpus.audit / "chains/audit.fixture/00000000000000000000.event.json");
    usk::state::StateRepository corpus_state(corpus.state);
    const auto compatible_state = corpus_state.read_installed("install.fixture");
    const auto compatible_chain = corpus_audit.read_and_validate_chain("audit.fixture");
    if (compatible_state.ownership_manifest_digest !=
            "5087da6c9d0dcdf1d5a8d11dd2a988c6c70bb06e70b2407bdef106e36cc2edb3" ||
        compatible_chain.size() != 1 || compatible_chain.front().event_digest !=
            "b27130773380781c6b5fe091173770aef362440834237af81bf23ff316d56153") {
        return 9;
    }
    return 0;
}

int main()
{
    try {
        return run();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 250;
    }
}
