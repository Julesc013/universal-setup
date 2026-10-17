// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_owned_publisher_retirement_internal.h"
#if defined(_WIN32)
#include "usk_completed_maintenance_records_internal.h"
#include "usk_maintenance_creator_records_internal.h"
#include "usk_owned_retirement_lease_history_internal.h"
#include "usk_owned_retirement_object_history_internal.h"
#include "usk_audit_repository.h"
#include "usk_install_lease.h"
#include "usk_maintenance_effect_journal.h"
#include "usk_publisher_consumer_access.h"
#include "usk_publisher_effect_execution_internal.h"
#include "usk_publisher_installation_lease.h"
#include "usk_publisher_security_descriptor.h"
#include "usk_record_io.h"
#include "usk_sha256.h"
#include <shellapi.h>
#include <algorithm>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace usk::lifecycle::detail {
namespace {
namespace fs = std::filesystem;
using json::Value;
using namespace usk::platform::windows;
using Record = PublisherRetirementRecord;
void require(bool ok, const char* why) {
    if (!ok) throw std::runtime_error(std::string("owned publisher retirement: ") + why);
}
bool equal(const Value& a, const Value& b) { return json::equal_values(a,b); }
std::string raw_sha(const std::string& text) {
    base::Sha256 sha;
    sha.update(reinterpret_cast<const unsigned char*>(text.data()),text.size());
    return sha.finish();
}
std::wstring wide(const std::string& text) { return fs::u8path(text).wstring(); }
std::string narrow(const std::wstring& text) { return fs::path(text).u8string(); }
std::string sequence(std::uint64_t n) {
    std::ostringstream out; out << std::setw(20) << std::setfill('0') << n; return out.str();
}
void members(const Value& v, std::initializer_list<const char*> keys) {
    require(v.as_object().size()==keys.size(),"record fields are not closed");
    for (const auto* key:keys) (void)v.at(key);
}
void require_seal(Value value, const char* key) {
    const auto expected=value.at(key).as_string();
    value.as_object().erase(key);
    require(json::sha256_canonical(value)==expected,"record seal differs");
}
Value parse(const Record& record) {
    require(record.bytes.size()<=16u*1024u*1024u && raw_sha(record.bytes)==record.sha256,
        "consumed bytes differ from held digest");
    json::ParseLimits limits; limits.max_bytes=16u*1024u*1024u; limits.max_values=2000000;
    auto value=json::parse(record.bytes,limits);
    const auto filename=std::filesystem::path(record.relative_path).filename().wstring();
    const auto container=std::filesystem::path(record.relative_path).parent_path().filename().wstring();
    const auto ends=[](const std::wstring& text,const std::wstring& suffix) {
        return text.size()>=suffix.size() && text.compare(text.size()-suffix.size(),suffix.size(),suffix)==0;
    };
    // Original journals and byte-preserved snapshots have their own ordered
    // serializer. The existing transaction decoder/extension checker validates
    // that grammar and its original raw digest; never canonicalize those bytes.
    const bool transaction=ends(filename,L".journal.json") || ends(container,L".native-maintenance-snapshots");
    if(!transaction) require(record.bytes==json::canonical(value)+"\n","record text differs from its role grammar");
    return value;
}
fs::path owned_relative(const std::string& text) {
    const auto path=fs::u8path(text);
    require(!path.empty() && !path.is_absolute() && path.root_name().empty() &&
        path.lexically_normal()==path && path!=fs::path("."),"unsafe relative member");
    for(const auto& part:path) require(part!=fs::path("..") && part!=fs::path("."),"relative path escaped");
    return path;
}
std::wstring volume_relative(const fs::path& path) {
    require(path.is_absolute() && path.root_name().wstring().size()==2u &&
        path.root_name().wstring()[1]==L':' && path==path.lexically_normal(),
        "reviewed path is not an absolute DOS volume path");
    return owned_relative(path.relative_path().generic_u8string()).make_preferred().wstring();
}
std::wstring join(const std::wstring& a,const std::wstring& b) {
    return (fs::path(a)/fs::path(b)).make_preferred().wstring();
}
std::wstring parent(const std::wstring& path) { return fs::path(path).parent_path().wstring(); }
struct Records {
    std::map<std::wstring,const Record*> files;
    std::map<std::wstring,const PublisherRetirementDirectoryMetadata*> directories;
    std::set<std::wstring> consumed_files, consumed_dirs;
    explicit Records(const OwnedPublisherRetirementHistory& v) {
        require(v.records.size()<=200000u && v.directories.size()<=200001u,"namespace count exceeds bound");
        // Native custody enumerates generic separators. Project exact held
        // members into one Windows key space without reopening any object.
        for(const auto& directory:v.directories) {
            const auto key=directory.first.empty()?std::wstring{}:
                owned_relative(narrow(directory.first)).make_preferred().wstring();
            require(directories.emplace(key,&directory.second).second,"duplicate normalized directory member");
        }
        std::size_t bytes=0;
        for(const auto& r:v.records) {
            auto path=owned_relative(narrow(r.relative_path));
            require(path.wstring()==r.relative_path,"file member name differs");
            const auto key=path.make_preferred().wstring();
            require(r.bytes.size()<=16u*1024u*1024u && r.bytes.size()<=64u*1024u*1024u-bytes,
                "aggregate record bytes exceed bound");
            bytes+=r.bytes.size();
            require(files.emplace(key,&r).second && !directories.count(key),"duplicate normalized member");
        }
    }
    const Record& file(const std::wstring& path) {
        auto it=files.find(path);
        if(it==files.end()) throw std::runtime_error("owned publisher retirement: required retained record is absent: "+narrow(path));
        consumed_files.insert(path); return *it->second;
    }
    Value value(const std::wstring& path) { return parse(file(path)); }
    const PublisherRetirementDirectoryMetadata& dir(const std::wstring& path) {
        auto it=directories.find(path);
        if(it==directories.end()) throw std::runtime_error("owned publisher retirement: required held directory is absent: "+narrow(path));
        consumed_dirs.insert(path); return *it->second;
    }
    std::vector<std::pair<std::string,std::string>> children(const std::wstring& path) {
        (void)dir(path);
        std::vector<std::pair<std::string,std::string>> out;
        for(const auto& entry:files) if(parent(entry.first)==path) {
            (void)parse(file(entry.first));
            out.emplace_back(narrow(fs::path(entry.first).filename().wstring()),entry.second->bytes);
        }
        return out;
    }
    void finish() {
        require(consumed_files.size()==files.size() && consumed_dirs.size()==directories.size(),
            "unknown, pending, retained payload or unexplained namespace member remains");
    }
};
std::vector<std::wstring> command_args(const Value& registration) {
    int count=0;
    auto* raw=CommandLineToArgvW(wide(registration.at("command").as_string()).c_str(),&count);
    require(raw!=nullptr,"registration command could not be decoded");
    const std::unique_ptr<wchar_t*,decltype(&LocalFree)> held(raw,LocalFree);
    require(count==11,"registration is outside the admitted-client profile");
    return {raw,raw+count};
}
void add_holders(const Value& value,std::map<std::string,Value>& holders) {
    if(value.type()==Value::Type::object) {
        const auto& object=value.as_object();
        for(const auto& pair:{std::pair<const char*,const char*>{"current_process_id","current_process_birth"},
                {"peer_process_id","peer_process_birth"}})
            if(object.count(pair.first) && object.count(pair.second)) {
                Value holder(Value::Object{{"process_id",value.at(pair.first)},
                    {"process_creation_time",value.at(pair.second)}});
                holders.emplace(json::canonical(holder),holder);
            }
        for(const auto& item:object) add_holders(item.second,holders);
    } else if(value.type()==Value::Type::array)
        for(const auto& item:value.as_array()) add_holders(item,holders);
}
void require_registration(const Value& broker, const Value& registration) {
    const auto& admission=broker.at("registered_admission");
    require(broker.at("service_configuration").at("command").as_string()==registration.at("command").as_string() &&
        admission.at("service_name").as_string()==registration.at("service_name").as_string() &&
        admission.at("service_sid").as_string()==registration.at("service_sid").as_string() &&
        admission.at("registration_sha256").as_string()==json::sha256_canonical(registration) &&
        equal(admission.at("target_identity").at("volume_identity"),registration.at("volume_identity")) &&
        admission.at("publisher_image").at("sha256").as_string()==registration.at("binary_sha256").as_string(),
        "historical broker differs from original protected registration");
}
Value consumer_grant(Value object,const std::string& consumer) {
    require(object.at("dacl_aces").as_array().size()==2u,"read grant lacks private preimage");
    object.as_object().at("dacl_aces").as_array().emplace_back(Value::Object{
        {"type",Value(std::uint64_t{ACCESS_ALLOWED_ACE_TYPE})},{"flags",Value(std::uint64_t{0})},
        {"access_mask",Value(static_cast<std::uint64_t>(publisher_consumer_read_access_mask()))},{"sid",Value(consumer)}});
    return object;
}
void require_initial_state(const InstallPlan& plan,const Value& snapshot,const Record& completion,
    const state::InstalledState& installed,const state::OwnershipManifest& ownership,
    const std::vector<audit::AuditEvent>& events)
{
    const auto& tx=snapshot.at("transaction_id").as_string();
    require(installed.install_id==plan.install_id && installed.transaction_id==tx &&
        installed.created_at==snapshot.at("applied_at").as_string() && installed.lifecycle_status=="installed" &&
        installed.product_id==plan.recipe.product_id && installed.product_version==plan.recipe.product_version &&
        installed.recipe_digest==plan.recipe.recipe_digest && installed.source_archive_digest==plan.recipe.source_archive_digest &&
        installed.provider_revision==plan.recipe.provider_revision && installed.component_selection==plan.recipe.components &&
        installed.target_root==plan.target_root.string() && installed.last_verification.status=="pass" &&
        ownership.install_id==plan.install_id && ownership.created_by_transaction_id==tx &&
        ownership.target_root==plan.target_root.string() && ownership.files.size()==plan.files.size() &&
        ownership.manifest_digest==installed.ownership_manifest_digest &&
        installed.ownership_manifest_ref=="ownership/"+ownership.manifest_id+".json" &&
        installed.audit_chain_id=="audit."+plan.install_id && events.size()>=2u,
        "initial installed, ownership or audit identity differs");
    std::set<std::string> directories;
    for(std::size_t i=0;i<plan.files.size();++i) {
        const auto& a=ownership.files[i];const auto& b=plan.files[i];
        require(std::tie(a.relative_path,a.sha256,a.size_bytes)==std::tie(b.relative_path,b.sha256,b.size_bytes),
            "initial ownership file differs from reviewed plan");
        for(auto path=fs::u8path(b.relative_path).parent_path();!path.empty();path=path.parent_path())
            directories.insert(path.generic_u8string());
    }
    require(std::vector<std::string>(directories.begin(),directories.end())==ownership.directories,
        "initial owned directory closure differs");
    for(std::size_t i=0;i<2u;++i) {
        const auto& e=events[i];
        require(e.created_at==snapshot.at("applied_at").as_string() && e.operation=="install_local" &&
            e.phase==(i==0u?"validated":"completed") && e.status=="pass" && e.transaction_id==tx &&
            e.plan_id==plan.plan_id && e.subject_type==(i==0u?"journal":"installation") &&
            e.subject_id==(i==0u?plan.plan_id:plan.install_id) &&
            e.details_digest==(i==0u?completion.sha256:installed.last_verification.report_digest) &&
            e.message==(i==0u?"held-handle protected publication closure verified":"protected managed install completed"),
            "initial audit events differ from protected completion");
    }
}
struct MaintenanceInput {
    transaction::TransactionSpec spec;
    Value roots,original,created,completed;
    std::string service_sid,resulting_status;
    std::string original_sha,created_sha;
    const std::vector<Value>& leases;
    std::string consumer;
};
void require_custody(Records& records,const std::wstring& transaction_root,
    const MaintenanceInput& input,const Value& snapshot,const std::string& transaction_text,
    const transaction::MaintenanceEffectInspection& effects)
{
    const auto& spec=input.spec;
    const auto base=join(transaction_root,wide(spec.transaction_id));
    const auto snaps=records.children(base+L".native-maintenance-snapshots");
    require(!snaps.empty() && snaps.size()<=100000u,"retained transaction snapshots absent or excessive");
    std::set<std::string> snapshots;
    std::size_t snapshot_bytes=0;
    for(const auto& item:snaps) {
        require(item.first.size()==69u && item.first.substr(64)==".json" &&
            raw_sha(item.second)==item.first.substr(0,64) && item.second.size()<=4u*1024u*1024u &&
            item.second.size()<=16u*1024u*1024u-snapshot_bytes,"retained snapshot identity or byte bound differs");
        snapshot_bytes+=item.second.size();
        transaction::TransactionSession::require_completed_transition_extension_bytes(spec,item.second,
            item.first.substr(0,64),transaction_text,raw_sha(transaction_text));
        require(snapshots.insert(item.first.substr(0,64)).second,"repeated retained snapshot");
    }
    const auto publication_snapshot=input.created.at("transaction_snapshot_sha256").as_string();
    require(snapshots.count(publication_snapshot)!=0u,"original publication snapshot is absent");
    const auto custody=records.children(base+L".native-maintenance-custody");
    require(!custody.empty() && custody.size()<=200000u,"original native custody is absent or excessive");
    std::map<std::uint64_t,const transaction::CompletedMaintenanceEffect*> completed;
    for(const auto& effect:effects.completed) completed.emplace(effect.intent_sequence,&effect);
    std::set<std::uint64_t> confirmed;
    std::string previous;
    bool publication=false;
    std::uint64_t prior_writer_generation=0;
    std::vector<Value> custody_values;
    std::map<std::uint64_t,Value> metadata_creations;
    for(std::size_t i=0;i<custody.size();++i) {
        require(custody[i].first==sequence(i)+".json","native custody sequence differs");
        auto value=json::parse(custody[i].second);
        members(value,{"schema","transaction_id","plan_digest","original_context_sha256","original_admission_sha256",
            "original_lease_ownership_sha256","writer_lease_ownership","sequence","kind","previous_record_sha256",
            "transaction_snapshot_sha256","pending_history_sha256","pending_intent_sequence","details"});
        require(value.at("schema").as_string()=="usk.publisher.maintenance_native_custody.v2" &&
            value.at("transaction_id").as_string()==spec.transaction_id && value.at("plan_digest").as_string()==spec.plan_digest &&
            value.at("original_context_sha256").as_string()==input.roots.at("roots_sha256").as_string() &&
            value.at("original_admission_sha256").as_string()==input.original_sha &&
            value.at("original_lease_ownership_sha256").as_string()==json::sha256_canonical(input.original.at("original_lease_ownership")) &&
            value.at("sequence").as_unsigned()==i &&
            equal(value.at("previous_record_sha256"),previous.empty()?Value{}:Value(previous)) &&
            snapshots.count(value.at("transaction_snapshot_sha256").as_string())!=0u &&
            value.at("writer_lease_ownership").at("operation_id").as_string()==spec.transaction_id &&
            value.at("writer_lease_ownership").at("operation").as_string()==spec.operation &&
            value.at("writer_lease_ownership").at("operation_context_sha256").as_string()==input.roots.at("roots_sha256").as_string() &&
            value.at("writer_lease_ownership").at("generation").as_unsigned()>=input.original.at("original_lease_ownership").at("generation").as_unsigned() &&
            value.at("writer_lease_ownership").at("generation").as_unsigned()<=input.completed.at("generation").as_unsigned() &&
            std::any_of(input.leases.begin(),input.leases.end(),[&](const Value& lease){
                return lease.at("status").as_string()=="active" && equal(lease,value.at("writer_lease_ownership"));}),
            "native custody changed original transaction, context, writer or hash chain");
        const auto writer_generation=value.at("writer_lease_ownership").at("generation").as_unsigned();
        require(writer_generation>=prior_writer_generation,"native custody writer generation moved backwards");
        prior_writer_generation=writer_generation;
        const auto kind=value.at("kind").as_string();const auto& details=value.at("details");
        if(kind=="confirmed_publication") {
            members(details,{"created_closure_sha256","root","parent","publication_transaction_snapshot_sha256"});
            auto expected=input.created.at("root");
            expected.as_object().at("native_name")=Value(input.created.at("target_parent").at("native_name").as_string()+
                "\\"+spec.target_root.filename().u8string());
            require(i==0u && !publication && details.at("created_closure_sha256").as_string()==input.created_sha &&
                details.at("publication_transaction_snapshot_sha256").as_string()==publication_snapshot &&
                value.at("transaction_snapshot_sha256").as_string()==publication_snapshot &&
                value.at("pending_history_sha256").type()==Value::Type::null_value &&
                value.at("pending_intent_sequence").type()==Value::Type::null_value &&
                equal(details.at("root"),expected) && equal(details.at("parent"),input.created.at("target_parent")),
                "native publication lacks original confirmed rename postimage");
            publication=true;
        } else {
            require(publication,"effect custody precedes publication");
            const auto n=value.at("pending_intent_sequence").as_unsigned();
            const auto intent=records.value(base+L".maintenance\\"+wide(sequence(n)+".json"));
            const auto effect=completed.find(n);
            require(effect!=completed.end() && intent.at("phase").as_string()=="intent" &&
                intent.at("sequence").as_unsigned()==n && intent.at("transaction_id").as_string()==spec.transaction_id &&
                intent.at("source_digest").as_string()==effects.source_digest &&
                intent.at("digest").as_string()==value.at("pending_history_sha256").as_string() &&
                intent.at("details").at("kind").as_string()==effect->second->kind &&
                equal(intent.at("details").at("effect"),effect->second->details),
                "custody intent is outside complete original effects");
            if(kind=="confirmed_effect") {
                members(details,{"intent_sequence","effect_kind","effect_details","outcome","result_digest","effect_transaction_snapshot_sha256"});
                require(details.at("intent_sequence").as_unsigned()==n && details.at("effect_kind").as_string()==effect->second->kind &&
                    equal(details.at("effect_details"),effect->second->details) &&
                    details.at("effect_transaction_snapshot_sha256").as_string()==value.at("transaction_snapshot_sha256").as_string() &&
                    details.at("outcome").as_string()==effect->second->outcome &&
                    equal(details.at("result_digest"),effect->second->result_digest.empty()?Value{}:Value(effect->second->result_digest)) &&
                    confirmed.insert(n).second &&
                    (effect->second->outcome=="applied" ||
                        (effect->second->outcome=="retained" && effect->second->kind=="remove_directory")),
                    "confirmed native effect differs from completed outcome");
            } else if(kind=="created_metadata") {
                members(details,{"setup_relative_path","object","parent","size_bytes","sha256"});
                const auto path=join(volume_relative(spec.state_root.parent_path()),
                    owned_relative(details.at("setup_relative_path").as_string()).wstring());
                const auto metadata=metadata_creations.emplace(n,details);
                require(metadata.second || equal(metadata.first->second,details),
                    "one metadata intent names different original native creations");
                const auto& effect_details=effect->second->details;
                if(effect->second->kind=="write_ownership")
                    require(path==join(volume_relative(spec.state_root),L"ownership\\"+wide(effect_details.at("manifest_id").as_string()+".json")),
                        "ownership creation selected a different metadata role");
                else if(effect->second->kind=="write_installed")
                    require(path==join(volume_relative(spec.state_root),L"installed\\"+wide(effect_details.at("install_id").as_string()+"."+spec.transaction_id+".json")),
                        "installed creation selected a different metadata role");
                else if(effect->second->kind=="append_audit") {
                    const auto event=records.value(path);
                    require(event.at("transaction_id").as_string()==spec.transaction_id &&
                        path==join(volume_relative(spec.audit_root),L"chains\\"+wide(effect_details.at("chain_id").as_string())+
                            L"\\"+wide(sequence(event.at("sequence").as_unsigned())+".event.json")),
                        "audit creation selected a different metadata role");
                }
                const auto& actual=records.file(path);
                require((effect->second->kind=="write_ownership" || effect->second->kind=="write_installed" ||
                        effect->second->kind=="append_audit") && details.at("size_bytes").as_unsigned()==actual.bytes.size() &&
                    details.at("sha256").as_string()==actual.sha256 &&
                    equal(details.at("object"),publisher_handle_observation_json(actual.object)) &&
                    equal(details.at("parent"),publisher_handle_observation_json(records.dir(parent(path)).object)),
                    "created metadata differs from original native postimage");
            } else if(kind=="consumer_read_grant") {
                members(details,{"root_role","relative_path","before","after","parent","native_identity","consumer_sid"});
                const auto relative=owned_relative(details.at("relative_path").as_string());
                const auto file=owned_relative(effect->second->details.at("relative_path").as_string());
                const auto below=file.lexically_relative(relative);
                require(spec.operation=="repair" && effect->second->kind=="replace_file" &&
                    details.at("root_role").as_string()=="installed" && details.at("consumer_sid").as_string()==input.consumer &&
                    equal(details.at("after"),consumer_grant(details.at("before"),input.consumer)) &&
                    !below.empty() && *below.begin()!=fs::path(".."),"read grant escaped original consumer or repaired file");
            } else if(kind=="later_created_directory" || kind=="created_owned_parent") {
                members(details,{"relative_path","object","parent","native_identity"});
                const auto relative=owned_relative(details.at("relative_path").as_string());
                if(kind=="later_created_directory")
                    require(*relative.begin()==fs::path("backup") && effect->second->kind=="backup_file",
                        "created backup directory differs from original effect");
                else {
                    const auto file=owned_relative(effect->second->details.at("relative_path").as_string());
                    const auto below=file.lexically_relative(relative);
                    const auto& dirs=snapshot.at("ownership_manifest").at("directories").as_array();
                    require(spec.operation=="repair" && effect->second->kind=="replace_file" &&
                        !below.empty() && below!=fs::path(".") && *below.begin()!=fs::path("..") &&
                        std::any_of(dirs.begin(),dirs.end(),[&](const Value& dir){
                            return owned_relative(dir.at("relative_path").as_string())==relative;}),
                        "created parent escaped original owned repair closure");
                }
            } else require(false,"unsupported native custody kind");
        }
        previous=raw_sha(custody[i].second);
        custody_values.push_back(std::move(value));
    }
    for(const auto& effect:effects.completed)
        require(effect.kind=="publish_target" || confirmed.count(effect.intent_sequence)!=0u,
            "completed effect lacks original confirmed custody");
    const auto historical=transaction::TransactionSession::decode_completed_history(spec,transaction_text);
    const auto artifact=records.value(base+L".maintenance-plan.json");
    require_owned_retirement_object_history(spec,input.original,input.created,artifact,historical.stream,effects,
        custody_values,input.consumer,input.service_sid,
        input.original.at("original_consumer_completion").at("original_visible_root_file_id").as_string(),input.resulting_status);

}
} // namespace
OwnedPublisherRetirementSelection validate_owned_publisher_retirement_history(
    const OwnedPublisherRetirementHistory& view,const std::wstring& service_name)
{
    Records records(view);
    const auto& registration=view.registration;
    members(registration,{"schema","service_name","service_sid","command","binary_sha256","volume_identity"});
    require(registration.at("schema").as_string()=="usk.publisher_registration_binding.v1" &&
        registration.at("service_name").as_string()==narrow(service_name),"retained registration identity differs");
    const auto args=command_args(registration);
    const auto consumer=narrow(args.at(10));const auto sid=registration.at("service_sid").as_string();
    require(args.at(1)==L"--service" && args.at(2)==service_name && args.at(3)==L"--no-receipt" &&
        args.at(4)==view.volume_root && args.at(5)==L"--reviewed-plan-envelope" &&
        args.at(8)==L"--service-admitted-client" && args.at(9)==L"--authorized-client-sid",
        "retirement registration command changed its original roles");
    const auto& snapshot_record=records.file(L"publication\\journal\\lab-reviewed-plan.json");
    const auto snapshot=parse(snapshot_record);
    const auto& prepared_record=records.file(L"publication\\journal\\lab-prepared-evidence.json");
    const auto& visible_record=records.file(L"publication\\journal\\lab-visible-evidence.json");
    const auto& completion_record=records.file(L"publication\\state\\lab-installed-state.json");
    const auto prepared=parse(prepared_record), visible=parse(visible_record), completion=parse(completion_record);
    const auto plan=decode_owned_retirement_install_history(snapshot_record.bytes,prepared_record.bytes,
        visible_record.bytes,completion_record.bytes,service_name,sid,consumer);
    const auto setup=volume_relative(plan.roots.state_root.parent_path());
    require(fs::path(setup).parent_path().empty(),"setup root is outside the admitted single-component profile");
    const auto state_root=join(setup,L"state"),transactions=join(state_root,L"transactions");
    for(const auto& path:{std::wstring{},setup,state_root,join(state_root,L"installed"),join(state_root,L"ownership"),
            join(state_root,L"leases"),transactions,join(setup,L"audit"),join(setup,L"audit\\chains"),
            join(setup,L"pending"),join(setup,L"staging"),std::wstring(L"installation-operations"),std::wstring(L"publication"),
            std::wstring(L"publication\\journal"),std::wstring(L"publication\\state"),std::wstring(L"publication\\staging"),
            std::wstring(L"publication\\destination")}) (void)records.dir(path);
    const auto& anchors=prepared.at("protected_anchors");
    require(equal(anchors.at("boundary"),publisher_handle_observation_json(records.dir(L"").object)),
        "initial native volume boundary differs");
    for(const auto& pair:{std::pair<const char*,const wchar_t*>{"destination_parent",L"publication\\destination"},
            {"journal",L"publication\\journal"},{"state",L"publication\\state"},{"staging",L"publication\\staging"}})
        require(equal(anchors.at(pair.first),publisher_handle_observation_json(records.dir(pair.second).object)),
            "publication anchor changed its original native identity");
    require(anchors.at("chain").as_array().size()==1u &&
        anchors.at("chain").as_array()[0].at("component").as_string()=="publication" &&
        equal(anchors.at("chain").as_array()[0].at("object"),publisher_handle_observation_json(records.dir(L"publication").object)),
        "publication namespace chain differs");
    const auto marker=records.value(join(setup,L".usk-owned-root.v1.json"));
    members(marker,{"schema","acceptance_root"});
    require(marker.at("schema").as_string()=="usk.setup_owned_root.v1" &&
        fs::u8path(marker.at("acceptance_root").as_string()).lexically_normal()==plan.target_root.root_path(),
        "original setup ownership marker differs");
    std::map<std::string,std::vector<std::pair<std::string,state::InstalledState>>> installed;
    std::map<std::string,std::string> installed_text;
    for(const auto& item:records.children(join(state_root,L"installed"))) {
        auto value=state::decode_installed_record(item.second);
        require(item.first==value.install_id+"."+value.transaction_id+".json" ||
            item.first==value.install_id+".json","installed filename differs from its own identity");
        installed_text.emplace(item.first,item.second);
        const auto id=value.install_id;
        installed[id].emplace_back(item.first,std::move(value));
    }
    require(!installed.empty(),"no complete owned installation history");
    OwnedPublisherRetirementSelection result;
    std::map<std::string,Value> holders;
    add_holders(prepared,holders);add_holders(visible,holders);
    for(const auto* evidence:{&prepared,&visible})
        for(const auto& phase:evidence->at("execution_phases").as_array()) {
            const auto& execution=phase.at("execution");
            require_registration(execution.at("broker_readback"),registration);
        }

    for(auto& installation:installed) {
        const auto& id=installation.first;
        require(id==plan.install_id,"installation has no matching original publication history");
        result.installation_ids.push_back(id);
        auto& states=installation.second;
        std::sort(states.begin(),states.end(),[](const auto& a,const auto& b){
            return std::tie(a.second.created_at,a.second.transaction_id)<std::tie(b.second.created_at,b.second.transaction_id);
        });
        for(const auto& state:states)
            require(fs::u8path(state.second.target_root).lexically_normal()==plan.target_root.lexically_normal(),
                "unmoved history changed its original installed root");
        require(states.back().second.lifecycle_status=="retired" &&
            states.back().second.last_verification.status=="pass","current owned installation is not successfully retired");
        Value::Array revision;
        for(const auto& item:installed_text)
            if(state::decode_installed_record(item.second).install_id==id)
                revision.emplace_back(Value::Object{{"record",Value(item.first)},{"sha256",Value(json::sha256_canonical(json::parse(item.second)))}});
        const auto install_component=L"install-"+wide(json::sha256_canonical(Value(id)));
        const auto lease_path=join(join(state_root,L"leases"),install_component);
        const auto operation_path=join(L"installation-operations",install_component);
        (void)records.dir(join(lease_path,L"pending"));(void)records.dir(operation_path);(void)records.dir(join(operation_path,L"pending"));
        const auto lease_bytes=records.children(lease_path);
        std::vector<Value> leases;
        for(const auto& item:lease_bytes) {
            auto lease=json::parse(item.second);transaction::require_install_lease_record(lease);
            const auto expected="g"+sequence(lease.at("generation").as_unsigned())+
                (lease.at("status").as_string()=="active"?"-active.json":"-terminal.json");
            require(item.first==expected,"lease filename differs from its generation/role");
            if(lease.at("status").as_string()=="active")
                holders.emplace(json::canonical(lease.at("holder")),lease.at("holder"));
            leases.push_back(std::move(lease));
        }
        const auto spans=decode_owned_retirement_lease_history(leases,id,records.dir(state_root).lease_root_identity,
            json::sha256_canonical(Value(std::move(revision))));
        const auto audit_path=join(join(setup,L"audit\\chains"),wide(states.front().second.audit_chain_id));
        const auto audit_bytes=records.children(audit_path);
        std::vector<audit::AuditEvent> audit_events;std::string previous;
        for(const auto& item:audit_bytes) {
            auto event=audit::decode_audit_chain_record(item.second,states.front().second.audit_chain_id,item.first,
                audit_events.size(),previous);
            previous=event.event_digest;audit_events.push_back(std::move(event));
        }
        std::map<std::string,std::pair<std::string,state::InstalledState>> by_tx;
        for(const auto& state:states) require(by_tx.emplace(state.second.transaction_id,state).second,"duplicate installed transaction");
        std::size_t completed_operations=0;
        std::map<std::string,std::string> seen_states;
        std::string previous_transaction;
        const auto prefix_revision=[&] {
            Value::Array entries;
            for(const auto& entry:seen_states)
                entries.emplace_back(Value::Object{{"record",Value(entry.first)},{"sha256",Value(entry.second)}});
            return json::sha256_canonical(Value(std::move(entries)));
        };
        for(const auto& span:spans) {
            const auto& lease=span.original_active;const auto tx=lease.at("operation_id").as_string();
            const auto operation=lease.at("operation").as_string();
            const auto op_base=join(operation_path,L"operation-"+wide(json::sha256_canonical(Value(tx))));
            const auto context=records.value(op_base+L".json"), roots=records.value(op_base+L"-roots.json");
            members(context,{"schema","install_id","operation","operation_id","volume_root_identity","initial_state_revision","reviewed_snapshot","context_sha256"});
            members(roots,{"schema","install_id","operation_id","context_sha256","setup_root_identity","state_root_identity","roots_sha256"});
            require_seal(context,"context_sha256");require_seal(roots,"roots_sha256");
            require(context.at("schema").as_string()==(operation=="install_local"?"usk.installation_operation_context.v1":"usk.installation_operation_context.v2") &&
                roots.at("schema").as_string()=="usk.installation_operation_roots.v1" &&
                context.at("install_id").as_string()==id && roots.at("install_id").as_string()==id &&
                context.at("operation_id").as_string()==tx && roots.at("operation_id").as_string()==tx &&
                context.at("operation").as_string()==operation &&
                equal(context.at("volume_root_identity"),records.dir(L"").lease_root_identity) &&
                equal(roots.at("setup_root_identity"),records.dir(setup).lease_root_identity) &&
                equal(roots.at("state_root_identity"),records.dir(state_root).lease_root_identity) &&
                roots.at("context_sha256").as_string()==context.at("context_sha256").as_string() &&
                roots.at("roots_sha256").as_string()==lease.at("operation_context_sha256").as_string(),
                "operation membership, native roots or context seals differ");
            require(lease.at("expected_state_revision").as_string()==prefix_revision(),
                "operation did not start from the exact preceding installed record set");
            if(span.repeated_completion) {
                require(span.completed.at("result_state_revision").as_string()==prefix_revision(),
                    "repeated completion changed installed record set");
                continue;
            }
            ++completed_operations;
            require(context.at("initial_state_revision").as_string()==lease.at("expected_state_revision").as_string(),
                "original operation entry revision differs");
            auto resulting=by_tx.find(tx);require(resulting!=by_tx.end(),"completed operation lacks installed snapshot");
            auto ownership=[&](const state::InstalledState& value)->std::string {
                const auto relative=owned_relative(value.ownership_manifest_ref);
                require(relative.parent_path()==fs::path("ownership"),"ownership reference escaped its role");
                return records.file(join(state_root,relative.wstring())).bytes;
            };
            const auto own_text=ownership(resulting->second.second);
            const auto own=state::decode_ownership_record(own_text,fs::u8path(resulting->second.second.ownership_manifest_ref).stem().u8string());
            if(operation=="install_local") {
                require(equal(context.at("reviewed_snapshot"),snapshot) && tx==snapshot.at("transaction_id").as_string(),
                    "install context differs from complete publication");
                require_initial_state(plan,snapshot,completion_record,resulting->second.second,own,audit_events);
                const auto reservation=records.value(op_base+L"-bootstrap-g"+wide(sequence(lease.at("generation").as_unsigned()))+L".json");
                members(reservation,{"schema","context_sha256","install_id","operation_id","ownership","publication_absent","reservation_sha256","roots_sha256","volume_root_identity"});
                require_seal(reservation,"reservation_sha256");
                require(reservation.at("schema").as_string()=="usk.publication_bootstrap_reservation.v1" &&
                    reservation.at("context_sha256").as_string()==context.at("context_sha256").as_string() &&
                    reservation.at("roots_sha256").as_string()==roots.at("roots_sha256").as_string() &&
                    reservation.at("install_id").as_string()==id && reservation.at("operation_id").as_string()==tx &&
                    reservation.at("publication_absent").as_boolean() && equal(reservation.at("ownership"),lease) &&
                    equal(reservation.at("volume_root_identity"),context.at("volume_root_identity")),
                    "initial bootstrap reservation differs from its completed lease");
            } else {
                const auto& saved=context.at("reviewed_snapshot");
                const auto& reviewed=saved.at("reviewed_plan");
                const auto original_id=saved.at("installed_state").at("transaction_id").as_string();
                const auto original_state=by_tx.find(original_id);
                require(original_id==previous_transaction,"maintenance skipped the immediately preceding completed generation");
                require(original_state!=by_tx.end() && original_state->second.second.created_at<resulting->second.second.created_at &&
                    saved.at("install_id").as_string()==id && saved.at("operation").as_string()==operation &&
                    equal(saved.at("volume_root_identity"),context.at("volume_root_identity")) &&
                    equal(saved.at("setup_root_identity"),roots.at("setup_root_identity")) &&
                    equal(saved.at("state_root_identity"),roots.at("state_root_identity")),
                    "maintenance selected unrelated original state or native roots");
                const auto& original_text=installed_text.at(original_state->second.first);
                require(equal(json::parse(original_text),saved.at("installed_state")) &&
                    equal(json::parse(ownership(original_state->second.second)),saved.at("ownership_manifest")),
                    "maintenance immutable original state differs from retained bytes");
                transaction::TransactionSpec spec;
                spec.transaction_id=tx;spec.plan_id=reviewed.at("plan_id").as_string();
                spec.plan_digest=saved.at("apply_request").at("reviewed_plan_digest").as_string();spec.operation=operation;
                spec.staging_parent=fs::u8path(reviewed.at("staging_parent").as_string());
                spec.state_root=fs::u8path(reviewed.at("state_root").as_string());
                spec.audit_root=fs::u8path(reviewed.at("audit_root").as_string());
                const auto transaction_text=records.file(join(transactions,wide(tx)+L".journal.json")).bytes;
                const auto transaction_value=json::parse(transaction_text);
                for(const auto& root:transaction_value.at("roots").as_array())
                    if(root.at("role").as_string()=="target") {
                        require(spec.target_root.empty(),"transaction repeats its target role");
                        spec.target_root=fs::u8path(root.at("root").as_string());
                    }
                require(!spec.target_root.empty(),"transaction target role is absent");
                require(spec.target_root.lexically_normal()==plan.target_root.parent_path()/(".usk-"+operation+"-"+tx),
                    "maintenance target escaped its fixed operation role");

                require(spec.state_root.lexically_normal()==plan.roots.state_root.lexically_normal() &&
                    spec.audit_root.lexically_normal()==plan.roots.audit_root.lexically_normal() &&
                    spec.staging_parent.lexically_normal()==plan.roots.staging_parent.lexically_normal(),
                    "maintenance changed its metadata role roots");
                CompletedMaintenanceHistoryBytes bytes;
                bytes.transaction=transaction_text;
                const auto effect_path=join(transactions,wide(tx)+L".maintenance");
                bytes.effect_directory_identity=records.dir(effect_path).journal_identity;
                bytes.effects=records.children(effect_path);bytes.reviewed_plan=records.file(join(transactions,wide(tx)+L".maintenance-plan.json")).bytes;
                bytes.original_installed=original_text;bytes.original_ownership=ownership(original_state->second.second);
                bytes.resulting_installed=installed_text.at(resulting->second.first);bytes.resulting_ownership=own_text;bytes.audit=audit_bytes;
                (void)decode_completed_maintenance_history(spec,bytes);
                const auto complete=transaction::TransactionSession::decode_completed_history(spec,transaction_text);
                transaction::MaintenanceEffectRecordReader reader(spec,bytes.effect_directory_identity,complete.stream.source_digest,bytes.effects.size(),true);
                for(const auto& item:bytes.effects) reader.consume(item.first,item.second);
                const auto effects=reader.finish();
                const auto& original_record=records.file(join(transactions,wide(tx)+L".native-maintenance-original.json"));
                const auto& created_record=records.file(join(transactions,wide(tx)+L".native-maintenance-created.json"));
                const auto original=decode_maintenance_original_custody_record(original_record.bytes);
                const auto created=decode_maintenance_created_closure_record(created_record.bytes,tx,spec.plan_digest);
                require_publisher_effect_maintenance_original_record(original,saved.at("apply_request"),service_name);
                require_registration(original.at("broker_readback"),registration);add_holders(original,holders);
                require(equal(original.at("original_lease_ownership"),lease),"maintenance creator differs from original completed lease span");
                require_maintenance_created_closure_binding(created,original,roots.at("roots_sha256").as_string(),
                    original_record.sha256,json::sha256_canonical(lease));
                const auto& original_completion=original.at("original_consumer_completion");
                require(created.at("source_context").as_string()==effects.source_context &&
                    original_completion.at("completion_record_sha256").as_string()==completion_record.sha256 &&
                    original_completion.at("prepared_record_sha256").as_string()==prepared_record.sha256 &&
                    original_completion.at("visible_record_sha256").as_string()==visible_record.sha256 &&
                    original_completion.at("reviewed_snapshot_sha256").as_string()==snapshot_record.sha256 &&
                    original_completion.at("original_visible_root_file_id").as_string()==completion.at("visible_root_file_id").as_string() &&
                    original_completion.at("original_transaction_id").as_string()==snapshot.at("transaction_id").as_string() &&
                    original_completion.at("install_id").as_string()==id &&
                    original_completion.at("consumer_read_sid").as_string()==consumer &&
                    original_completion.at("setup_root").as_string()==snapshot.at("setup_root").as_string(),
                    "maintenance changed original install or consumer completion");
                require(equal(created.at("root_parent"),publisher_handle_observation_json(records.dir(volume_relative(spec.staging_parent)).object)) &&
                    equal(created.at("target_parent"),publisher_handle_observation_json(records.dir(volume_relative(spec.target_root.parent_path())).object)),
                    "original maintenance publication parents changed");
                require_custody(records,transactions,{spec,roots,original,created,span.completed,sid,resulting->second.second.lifecycle_status,original_record.sha256,created_record.sha256,leases,consumer},
                    saved,transaction_text,effects);
                result.reviewed_volume_paths.push_back(spec.target_root);
            }
            require(seen_states.emplace(resulting->second.first,
                json::sha256_canonical(json::parse(installed_text.at(resulting->second.first)))).second,
                "completed operation repeats an installed snapshot");
            require(span.completed.at("result_state_revision").as_string()==prefix_revision(),
                "operation completion differs from exact installed record postimage");
            previous_transaction=tx;
            result.reviewed_volume_paths.emplace_back(resulting->second.second.target_root);
        }
        require(states.size()==completed_operations && audit_events.size()==completed_operations+1u,
            "installed or audit history contains an unaccounted operation");
    }
    records.finish();
    for(auto& holder:holders) result.historical_holders.push_back(std::move(holder.second));
    result.reviewed_volume_paths.push_back(plan.target_root);
    result.reviewed_volume_paths.push_back(plan.roots.state_root);
    result.reviewed_volume_paths.push_back(plan.roots.audit_root);
    result.reviewed_volume_paths.push_back(plan.roots.staging_parent);
    return result;
}

void retire_owned_publisher(const std::wstring& service_name)
{
    PublisherOwnedRetirementCustody custody(service_name);
    OwnedPublisherRetirementHistory history;
    history.registration=custody.registration();history.volume_root=custody.volume_root();
    history.records=custody.records();
    history.directories.emplace(L"",custody.observe_directory_metadata(L""));
    for(const auto& path:custody.directories())
        require(history.directories.emplace(path,custody.observe_directory_metadata(path)).second,
            "held native directory appears twice");
    std::set<std::string> ids;
    for(const auto& record:history.records)
        if(fs::path(parent(record.relative_path)).filename()==fs::path(L"installed"))
            ids.insert(state::decode_installed_record(record.bytes).install_id);
    custody.acquire_installations({ids.begin(),ids.end()});
    custody.require_unchanged();
    const auto selection=validate_owned_publisher_retirement_history(history,service_name);
    require(selection.installation_ids==std::vector<std::string>(ids.begin(),ids.end()),
        "full validated installation set differs from native admission");
    for(const auto& holder:selection.historical_holders) {
        const auto observed=observe_publisher_previous_lease_holder(holder);
        require(observed==transaction::InstallLeasePreviousHolder::ended ||
            observed==transaction::InstallLeasePreviousHolder::identity_reused,"historical native holder is live or uncertain");
    }
    for(const auto& path:selection.reviewed_volume_paths) {
        (void)volume_relative(path);
        wchar_t actual[MAX_PATH]{};
        require(GetVolumeNameForVolumeMountPointW(path.root_path().c_str(),actual,MAX_PATH)!=FALSE &&
            CompareStringOrdinal(actual,-1,history.volume_root.c_str(),-1,TRUE)==CSTR_EQUAL,
            "reviewed DOS root no longer names the original held volume");
    }
    custody.require_unchanged();
    custody.retire_after_owned_validation();
}
} // namespace usk::lifecycle::detail
#endif
