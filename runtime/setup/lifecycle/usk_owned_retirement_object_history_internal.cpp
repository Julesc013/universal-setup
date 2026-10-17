// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
#include "usk_owned_retirement_object_history_internal.h"
#if defined(_WIN32)
#include "usk_publisher_security_descriptor.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>
#include <limits>
#include <utility>

namespace usk::lifecycle::detail {
namespace {
namespace fs=std::filesystem;
using json::Value;
void need(bool ok,const char* why) {
    if(!ok) throw std::runtime_error(std::string("retirement object history: ")+why);
}
bool same(const Value& a,const Value& b) { return json::equal_values(a,b); }
void fields(const Value& v,std::initializer_list<const char*> names) {
    need(v.as_object().size()==names.size(),"object record is not closed");
    for(const auto* name:names) (void)v.at(name);
}
std::string relative(const std::string& name,bool root=false) {
    if(root && name.empty()) return {};
    const auto path=fs::u8path(name);
    need(!path.empty() && !path.is_absolute() && path.root_name().empty() &&
        path.lexically_normal()==path && path!=fs::path("."),"relative object role escaped");
    for(const auto& part:path) need(part!=fs::path("..") && part!=fs::path("."),"relative object role escaped");
    return path.generic_u8string();
}
std::string native_child(const std::string& root,const std::string& path) {
    if(path.empty()) return root;
    auto suffix=path;std::replace(suffix.begin(),suffix.end(),'/','\\');
    return root+"\\"+suffix;
}
std::string legacy_identity(const Value& object) {
    const auto full=object.at("file_id").as_string();
    need(full.size()==49u && full[16]==':' &&
        std::all_of(full.begin(),full.end(),[](char c){return c==':' || (c>='0' && c<='9') || (c>='a' && c<='f');}) &&
        std::count(full.begin(),full.end(),':')==1,"full native identity is invalid");
    const auto serial=std::stoull(full.substr(0,16),nullptr,16)&0xffffffffull;
    std::uint64_t file=0;
    for(unsigned i=0;i<8u;++i) file|=std::stoull(full.substr(17u+2u*i,2u),nullptr,16)<<(8u*i);
    const auto hex=[](std::uint64_t number) {
        const char digits[]="0123456789abcdef";std::string result(16,'0');
        for(unsigned i=0;i<16u;++i){result[15u-i]=digits[number&15u];number>>=4u;}return result;
    };
    return hex(serial)+":"+hex(file);
}
void shape(const Value& object,const std::string& name,bool directory,const std::string& service,
    const std::string& consumer,bool grant_allowed)
{
    fields(object,{"attributes","case_sensitive","dacl_aces","dacl_protected","file_id","link_count","native_name","owner_sid","reparse_tag"});
    (void)legacy_identity(object);
    const auto attributes=object.at("attributes").as_unsigned();
    need(attributes<=std::numeric_limits<std::uint32_t>::max() &&
        (attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))==(directory?FILE_ATTRIBUTE_DIRECTORY:0u) &&
        !object.at("case_sensitive").as_boolean() && object.at("dacl_protected").as_boolean() &&
        object.at("link_count").as_unsigned()==1u && object.at("reparse_tag").as_unsigned()==0u &&
        object.at("owner_sid").as_string()=="S-1-5-18" && object.at("native_name").as_string()==name,
        "native object identity, namespace, kind or protection differs");
    const auto& aces=object.at("dacl_aces").as_array();
    need(aces.size()==2u || (grant_allowed && aces.size()==3u),"native object has an unexpected access grant");
    for(std::size_t i=0;i<aces.size();++i) {
        fields(aces[i],{"access_mask","flags","sid","type"});
        need(aces[i].at("type").as_unsigned()==ACCESS_ALLOWED_ACE_TYPE && aces[i].at("flags").as_unsigned()==0u &&
            aces[i].at("sid").as_string()==(i==0u?"S-1-5-18":i==1u?service:consumer) &&
            aces[i].at("access_mask").as_unsigned()==(i<2u?FILE_ALL_ACCESS:
                usk::platform::windows::publisher_consumer_read_access_mask()),"native descriptor changed its exact owner roles");
    }
}
struct Object {
    Value facts;
    std::string identity,sha;
    std::uint64_t size=0;
    bool directory=false;
};
using Objects=std::map<std::string,Object>;
const Object& object_at(const Objects& objects,const std::string& key) {
    const auto it=objects.find(key);need(it!=objects.end(),"object parent or role is absent");return it->second;
}
std::string parent(const std::string& key) { return fs::u8path(key).parent_path().generic_u8string(); }
Object renamed(Object object,const std::string& name) {
    object.facts.as_object().at("native_name")=Value(name);return object;
}
void require_parent(const Value& actual,const Objects& objects,const std::string& key) {
    need(same(actual,object_at(objects,parent(key)).facts),"native parent differs from its bound role");
}
void erase_empty_directory(Objects& objects,const std::string& key) {
    const auto& object=object_at(objects,key);need(object.directory,"directory effect names a file");
    const auto prefix=key.empty()?std::string{}:key+"/";
    for(const auto& item:objects)
        need(item.first==key || (!prefix.empty() && item.first.rfind(prefix,0)!=0),"directory effect has retained children");
    objects.erase(key);
}
} // namespace

void require_owned_retirement_object_history(
    const transaction::TransactionSpec& spec,const Value& original,const Value& created,const Value& artifact,
    const transaction::StreamJournal& stream,const transaction::MaintenanceEffectInspection& effects,
    const std::vector<Value>& custody,const std::string& consumer,const std::string& service,
    const std::string& visible_id,const std::string& resulting_status)
{
    Objects installed,operation;
    const auto& installed_root=original.at("installed_root");
    const auto installed_name=installed_root.at("native_name").as_string();
    const auto& stage_root=created.at("root");
    const auto stage_name=stage_root.at("native_name").as_string();
    const auto operation_name=created.at("target_parent").at("native_name").as_string()+"\\"+spec.target_root.filename().u8string();
    shape(installed_root,installed_name,true,service,consumer,true);
    shape(stage_root,stage_name,true,service,consumer,false);
    need(installed_root.at("file_id").as_string()==visible_id &&
        original.at("installed_root_journal_identity").as_string()==legacy_identity(installed_root) &&
        created.at("root_native_identity").as_string()==legacy_identity(stage_root) &&
        stream.publication_root_identity==legacy_identity(stage_root) &&
        stage_name==created.at("root_parent").at("native_name").as_string()+"\\.usk-stage-"+spec.transaction_id &&
        spec.target_root.filename().u8string()==".usk-"+spec.operation+"-"+spec.transaction_id,
        "original or created root lost its publication identity and role");
    installed.emplace("",Object{installed_root,legacy_identity(installed_root),{},0,true});
    const auto& originals=original.at("original_objects").as_array();
    const auto& expected=artifact.at("original_owned_objects").as_array();
    need(originals.size()==expected.size()+1u,"original object closure differs from reviewed effects");
    std::map<std::string,const Value*> expected_originals;
    for(const auto& item:expected)
        need(expected_originals.emplace(relative(item.at("relative_path").as_string()),&item).second,
            "reviewed original role appears twice");
    std::set<std::string> all_original_names,original_ids{installed_root.at("file_id").as_string()};
    for(std::size_t i=0;i<originals.size();++i) {
        const auto& item=originals[i];
        const auto type=item.at("type").as_string();
        need(type=="file" || type=="directory","original object has an unsupported kind");
        if(type=="file") fields(item,{"native_identity","object","parent","present","relative_path","sha256","size_bytes","type"});
        else fields(item,{"native_identity","object","parent","present","relative_path","type"});
        const auto name=relative(item.at("relative_path").as_string(),true);
        need(all_original_names.insert(name).second,"original object role appears twice");
        if(name.empty()) {
            need(item.at("type").as_string()=="directory" && item.at("present").as_boolean() &&
                item.at("native_identity").as_string()==legacy_identity(installed_root) &&
                same(item.at("object"),installed_root) && same(item.at("parent"),created.at("target_parent")),
                "original root observation differs from its bound publication parent");
            continue;
        }
        const auto selected=expected_originals.find(name);
        need(selected!=expected_originals.end(),"native original observation has an unexplained role");
        auto projection=item;projection.as_object().erase("object");projection.as_object().erase("parent");
        need(same(projection,*selected->second),"native original observation differs from reviewed original effects");
        expected_originals.erase(selected);
        if(!item.at("present").as_boolean()) {
            need(item.at("object").type()==Value::Type::null_value,"absent object retains native custody");
            continue;
        }
        const bool directory=item.at("type").as_string()=="directory";
        shape(item.at("object"),native_child(installed_name,name),directory,service,consumer,true);
        need(item.at("native_identity").as_string()==legacy_identity(item.at("object")) &&
            original_ids.insert(item.at("object").at("file_id").as_string()).second,"original object identity aliases or differs");
        installed.emplace(name,Object{item.at("object"),item.at("native_identity").as_string(),
            directory?std::string{}:item.at("sha256").as_string(),directory?0u:item.at("size_bytes").as_unsigned(),directory});
    }
    need(expected_originals.empty() && all_original_names.count("")==1u,"original native closure omits a reviewed role");
    for(const auto& item:originals) if(item.at("present").as_boolean() && !item.at("relative_path").as_string().empty())
        require_parent(item.at("parent"),installed,relative(item.at("relative_path").as_string()));
    need(original_ids.count(stage_root.at("file_id").as_string())==0u,"created root aliases an original object");
    const auto context=json::parse(effects.source_context);
    need(installed_name==created.at("target_parent").at("native_name").as_string()+"\\"+
        fs::u8path(context.at("installed_root").at("root").as_string()).filename().u8string(),
        "original installed root changed native namespace role");
    operation.emplace("",renamed(Object{stage_root,legacy_identity(stage_root),{},0,true},operation_name));
    std::map<std::string,const transaction::StreamEntryObservation*> outputs;
    std::set<std::string> expected_directories,created_ids{stage_root.at("file_id").as_string()};
    for(const auto& entry:stream.entries) {
        const auto name=relative(entry.relative_path);
        need(outputs.emplace(name,&entry).second,"staged output role appears twice");
        for(auto path=fs::u8path(name).parent_path();!path.empty();path=path.parent_path())
            expected_directories.insert(path.generic_u8string());
    }
    for(const auto& item:created.at("created_objects").as_array()) {
        fields(item,{"native_identity","object","relative_path","sha256","size_bytes"});
        const auto name=relative(item.at("relative_path").as_string());
        const bool directory=(item.at("object").at("attributes").as_unsigned()&FILE_ATTRIBUTE_DIRECTORY)!=0u;
        shape(item.at("object"),native_child(stage_name,name),directory,service,consumer,false);
        need(item.at("native_identity").as_string()==legacy_identity(item.at("object")) &&
            created_ids.insert(item.at("object").at("file_id").as_string()).second &&
            original_ids.count(item.at("object").at("file_id").as_string())==0u,"created object identity aliases or differs");
        Object object{item.at("object"),item.at("native_identity").as_string(),{},0,directory};
        if(directory) need(expected_directories.erase(name)==1u &&
            item.at("sha256").as_string().empty() && item.at("size_bytes").as_unsigned()==0u,
            "created directory is outside staged closure");
        else {
            const auto it=outputs.find(name);need(it!=outputs.end(),"created file is outside staged closure");
            need(item.at("sha256").as_string()==it->second->sha256 &&
                item.at("size_bytes").as_unsigned()==it->second->expected_size &&
                item.at("native_identity").as_string()==it->second->output_identity,"created file differs from staged output");
            object.sha=item.at("sha256").as_string();object.size=item.at("size_bytes").as_unsigned();outputs.erase(it);
        }
        need(operation.emplace(name,renamed(std::move(object),native_child(operation_name,name))).second,"created role appears twice");
    }
    need(outputs.empty() && expected_directories.empty(),"created native closure omits staged objects");
    const auto original_created_objects=operation;
    std::map<std::uint64_t,const transaction::CompletedMaintenanceEffect*> by_intent;
    for(const auto& effect:effects.completed) by_intent.emplace(effect.intent_sequence,&effect);
    for(const auto& record:custody) {
        const auto kind=record.at("kind").as_string();const auto& details=record.at("details");
        if(kind=="confirmed_publication") continue;
        const auto it=by_intent.find(record.at("pending_intent_sequence").as_unsigned());
        need(it!=by_intent.end(),"native role record has no completed intent");
        const auto& effect=*it->second;
        if(kind=="later_created_directory" || kind=="created_owned_parent") {
            auto& objects=kind=="later_created_directory"?operation:installed;
            const auto& root=kind=="later_created_directory"?operation_name:installed_name;
            const auto name=relative(details.at("relative_path").as_string());
            shape(details.at("object"),native_child(root,name),true,service,consumer,false);
            need(details.at("native_identity").as_string()==legacy_identity(details.at("object")) &&
                objects.count(name)==0u,"new directory repeats or changes an original role");
            require_parent(details.at("parent"),objects,name);
            objects.emplace(name,Object{details.at("object"),details.at("native_identity").as_string(),{},0,true});
        } else if(kind=="consumer_read_grant") {
            const auto name=relative(details.at("relative_path").as_string());
            const auto file=relative(effect.details.at("relative_path").as_string());
            auto found=installed.find(name);
            if(name==file) {
                const auto source="payload/"+name;
                const auto staged=operation.find(source);
                auto next=renamed(object_at(original_created_objects,source),native_child(installed_name,name));
                need(same(next.facts,details.at("before")),"file grant differs from original replacement identity");
                if(staged!=operation.end()) {
                    need(found==installed.end(),"file grant would overwrite an installed object role");
                    operation.erase(staged);installed.emplace(name,std::move(next));
                } else need(found!=installed.end() && same(found->second.facts,next.facts),
                    "file grant has no confirmed original replacement");
                found=installed.find(name);
            }
            need(found!=installed.end() && same(found->second.facts,details.at("before")) &&
                details.at("native_identity").as_string()==found->second.identity,"grant changed its original native object");
            require_parent(details.at("parent"),installed,name);
            shape(details.at("after"),native_child(installed_name,name),found->second.directory,service,consumer,true);
            found->second.facts=details.at("after");
        } else if(kind=="confirmed_effect") {
            const auto& data=effect.details;
            if(effect.kind=="backup_file") {
                const auto name=relative(data.at("relative_path").as_string());const auto source=installed.find(name);
                need(source!=installed.end() && !source->second.directory &&
                    source->second.identity==data.at("native_identity").as_string() &&
                    source->second.sha==data.at("sha256").as_string() && source->second.size==data.at("size_bytes").as_unsigned(),
                    "backup differs from original installed object");
                const auto destination="backup/"+name;
                (void)object_at(operation,parent(destination));
                need(operation.emplace(destination,renamed(source->second,native_child(operation_name,destination))).second,
                    "backup overwrote another role");installed.erase(source);
            } else if(effect.kind=="replace_file") {
                const auto name=relative(data.at("relative_path").as_string());
                const auto target=installed.find(name);
                if(target==installed.end()) {
                    const auto source=operation.find("payload/"+name);need(source!=operation.end(),"replacement lost its staged source");
                    (void)object_at(installed,parent(name));
                    installed.emplace(name,renamed(source->second,native_child(installed_name,name)));operation.erase(source);
                }
                const auto& object=object_at(installed,name);
                need(!object.directory && object.identity==data.at("native_identity").as_string() &&
                    object.sha==data.at("sha256").as_string() && object.size==data.at("size_bytes").as_unsigned(),
                    "replacement changed its original native output");
            } else if(effect.kind=="remove_file" || effect.kind=="remove_directory") {
                const auto role=data.at("root_role").as_string();
                need(role=="installed" || role=="operation_target","removal selected an unknown role");
                auto& objects=role=="installed"?installed:operation;
                const auto name=relative(data.at("relative_path").as_string(),effect.kind=="remove_directory");
                const auto& object=object_at(objects,name);
                need(object.identity==data.at("native_identity").as_string(),"removal changed native object identity");
                if(effect.kind=="remove_file") {
                    need(!object.directory && object.sha==data.at("sha256").as_string() &&
                        object.size==data.at("size_bytes").as_unsigned(),"removal changed original bytes");
                    objects.erase(name);
                } else if(effect.outcome=="applied") erase_empty_directory(objects,name);
            }
        }
    }
    need(operation.empty(),"completed operation retains created payload or directories");
    if(resulting_status=="retired") need(installed.empty(),"retired history retains an owned native object");
}
} // namespace usk::lifecycle::detail
#endif
