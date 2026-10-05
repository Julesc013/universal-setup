// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

#include "usk_publisher_creation_observation.h"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

using usk::json::Value;
using usk::platform::windows::publisher_creation_graph;

namespace {
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::string id(unsigned number) { return "0000000000001234:" + std::string(31, '0') + std::to_string(number); }
Value object(unsigned number) { return Value(Value::Object{{"file_id", Value(id(number))}}); }
} // namespace

int main() {
    try {
        // Ordinary callers cannot activate native service creation capture.
        // This absent-service check has no SCM creation or filesystem effects.
        bool refused = false;
        try {
            usk::platform::windows::PublisherCreationCapture capture(
                INVALID_HANDLE_VALUE, L"USK_NoService_Creation_Observation_Smoke");
        } catch (const std::runtime_error&) { refused = true; }
        check(refused, "ordinary process acquired service creation capture");

        // Pure graph controls only: these identities do not claim native birth.
        const Value anchors(Value::Object{{"boundary", object(1)},
            {"chain", Value(Value::Array{Value(Value::Object{
                {"component", Value("publication")}, {"object", object(2)}})})},
            {"staging", object(3)}, {"destination_parent", object(4)},
            {"state", object(5)}, {"journal", object(6)}});
        auto directory = object(8);
        directory.as_object().emplace("attributes", Value(std::uint64_t{FILE_ATTRIBUTE_DIRECTORY}));
        auto file = object(9);
        file.as_object().emplace("attributes", Value(std::uint64_t{FILE_ATTRIBUTE_ARCHIVE}));
        const Value tree(Value::Object{{"root", object(7)},
            {"descendants", Value(Value::Array{
                Value(Value::Object{{"relative_path", Value("dir")}, {"object", directory}}),
                Value(Value::Object{{"relative_path", Value("dir\\payload.bin")}, {"object", file}})})}});
        const auto graph = publisher_creation_graph(anchors, tree);
        check(graph.as_array().size() == 8 && graph.as_array()[6].at("file_id").as_string() == id(8) &&
            graph.as_array()[6].at("parent_file_id").as_string() == id(7) &&
            graph.as_array()[7].at("parent_file_id").as_string() == id(8) &&
            graph.as_array()[7].at("name").as_string() == "payload.bin" &&
            graph.as_array()[7].at("kind").as_string() == "file",
            "created graph failed to bind a nested child to its actual parent identity");
        auto reverse = tree;
        std::swap(reverse.as_object().at("descendants").as_array()[0],
            reverse.as_object().at("descendants").as_array()[1]);
        check(usk::json::canonical(publisher_creation_graph(anchors, reverse)) == usk::json::canonical(graph),
            "creation graph depends on enumeration order");
        const auto rejects = [&](const std::function<void(Value&, Value&)>& mutate) {
            auto bad_anchors = anchors;
            auto bad_tree = tree;
            mutate(bad_anchors, bad_tree);
            bool failed = false;
            try { (void)publisher_creation_graph(bad_anchors, bad_tree); }
            catch (const std::runtime_error&) { failed = true; }
            check(failed, "creation graph admitted contradictory parent or identity evidence");
        };
        rejects([](Value&, Value& v) { v.as_object().at("descendants").as_array().erase(
            v.as_object().at("descendants").as_array().begin()); });
        rejects([](Value&, Value& v) { v.as_object().at("root") = object(1); });
        rejects([](Value& v, Value&) { v.as_object().at("journal") = object(5); });
        rejects([](Value&, Value& v) { v.as_object().at("descendants").as_array()[0]
            .as_object().at("object").as_object().at("attributes") = Value(std::uint64_t{FILE_ATTRIBUTE_ARCHIVE}); });
        rejects([](Value&, Value& v) { v.as_object().at("descendants").as_array()[1]
            .as_object().at("relative_path") = Value("dir\\.."); });
        rejects([](Value& v, Value&) { v.as_object().at("chain").as_array()[0]
            .as_object().at("component") = Value("other"); });
        std::cout << "publisher creation observation controls passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
