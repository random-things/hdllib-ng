#include <google/protobuf/compiler/code_generator.h>
#include <google/protobuf/compiler/plugin.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/printer.h>
#include <google/protobuf/io/zero_copy_stream.h>

#include <map>
#include <memory>
#include <string>

namespace {

template <typename View> std::string CopyString(View value) {
    return std::string(value.data(), value.size());
}

std::string MethodEnumName(const google::protobuf::ServiceDescriptor* service,
                           const google::protobuf::MethodDescriptor* method) {
    return CopyString(service->name()) + "_" + CopyString(method->name());
}

std::string CppType(const google::protobuf::Descriptor* type) {
    std::string name = "::";
    for (char c : type->full_name()) {
        name += c == '.' ? ':' : c;
        if (c == '.') {
            name += ':';
        }
    }
    return name;
}

std::string JsonEscape(std::string_view value) {
    std::string out;
    for (const char c : value) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

void CollectFile(const google::protobuf::FileDescriptor* file,
                 std::map<std::string, const google::protobuf::FileDescriptor*>* files) {
    if (!file || file->package() != "hdl.rpc.v1" ||
        !files->emplace(CopyString(file->name()), file).second)
        return;
    for (int index = 0; index < file->dependency_count(); ++index)
        CollectFile(file->dependency(index), files);
}

std::string FieldType(const google::protobuf::FieldDescriptor* field) {
    if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE)
        return CopyString(field->message_type()->full_name());
    if (field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_ENUM)
        return CopyString(field->enum_type()->full_name());
    using Field = google::protobuf::FieldDescriptor;
    switch (field->type()) {
    case Field::TYPE_DOUBLE:
        return "double";
    case Field::TYPE_FLOAT:
        return "float";
    case Field::TYPE_INT64:
        return "int64";
    case Field::TYPE_UINT64:
        return "uint64";
    case Field::TYPE_INT32:
        return "int32";
    case Field::TYPE_FIXED64:
        return "fixed64";
    case Field::TYPE_FIXED32:
        return "fixed32";
    case Field::TYPE_BOOL:
        return "bool";
    case Field::TYPE_STRING:
        return "string";
    case Field::TYPE_BYTES:
        return "bytes";
    case Field::TYPE_UINT32:
        return "uint32";
    case Field::TYPE_SFIXED32:
        return "sfixed32";
    case Field::TYPE_SFIXED64:
        return "sfixed64";
    case Field::TYPE_SINT32:
        return "sint32";
    case Field::TYPE_SINT64:
        return "sint64";
    default:
        return "unknown";
    }
}

void CollectMessage(const google::protobuf::Descriptor* message,
                    std::map<std::string, const google::protobuf::Descriptor*>* messages,
                    std::map<std::string, const google::protobuf::EnumDescriptor*>* enums) {
    if (!messages->emplace(CopyString(message->full_name()), message).second)
        return;
    for (int index = 0; index < message->enum_type_count(); ++index)
        enums->emplace(CopyString(message->enum_type(index)->full_name()),
                       message->enum_type(index));
    for (int index = 0; index < message->nested_type_count(); ++index)
        CollectMessage(message->nested_type(index), messages, enums);
}

std::string BuildContract(const google::protobuf::FileDescriptor* service_file) {
    std::map<std::string, const google::protobuf::FileDescriptor*> files;
    std::map<std::string, const google::protobuf::Descriptor*> messages;
    std::map<std::string, const google::protobuf::EnumDescriptor*> enums;
    CollectFile(service_file, &files);
    for (const auto& [_, file] : files) {
        for (int index = 0; index < file->message_type_count(); ++index)
            CollectMessage(file->message_type(index), &messages, &enums);
        for (int index = 0; index < file->enum_type_count(); ++index)
            enums.emplace(CopyString(file->enum_type(index)->full_name()), file->enum_type(index));
    }
    std::string json = "{\n\"package\":\"hdl.rpc.v1\",\n\"services\":[\n";
    for (int s = 0; s < service_file->service_count(); ++s) {
        const auto* service = service_file->service(s);
        if (s)
            json += ",\n";
        json += "{\"name\":\"" + JsonEscape(service->name()) + "\",\"methods\":[";
        for (int m = 0; m < service->method_count(); ++m) {
            const auto* method = service->method(m);
            if (m)
                json += ',';
            json += "[\"" + JsonEscape(method->name()) + "\",\"" +
                    JsonEscape(method->input_type()->full_name()) + "\",\"" +
                    JsonEscape(method->output_type()->full_name()) + "\"," +
                    (method->server_streaming() ? "true" : "false") + "]";
        }
        json += "]}";
    }
    json += "\n],\n\"messages\":[\n";
    bool first_message = true;
    for (const auto& [name, message] : messages) {
        if (!first_message)
            json += ",\n";
        first_message = false;
        json += "{\"name\":\"" + JsonEscape(name) + "\",\"fields\":[";
        for (int index = 0; index < message->field_count(); ++index) {
            const auto* field = message->field(index);
            if (index)
                json += ',';
            json += "[\"" + JsonEscape(field->name()) + "\"," + std::to_string(field->number()) +
                    ",\"" + JsonEscape(FieldType(field)) + "\"," +
                    (field->is_repeated() ? "true" : "false");
            if (field->containing_oneof())
                json += ",\"" + JsonEscape(field->containing_oneof()->name()) + "\"";
            json += ']';
        }
        json += "]}";
    }
    json += "\n],\n\"enums\":[\n";
    bool first_enum = true;
    for (const auto& [name, value] : enums) {
        if (!first_enum)
            json += ",\n";
        first_enum = false;
        json += "{\"name\":\"" + JsonEscape(name) + "\",\"values\":[";
        for (int index = 0; index < value->value_count(); ++index) {
            if (index)
                json += ',';
            json += "[\"" + JsonEscape(value->value(index)->name()) + "\"," +
                    std::to_string(value->value(index)->number()) + "]";
        }
        json += "]}";
    }
    json += "\n]\n}\n";
    return json;
}

class HdlRpcGenerator final : public google::protobuf::compiler::CodeGenerator {
  public:
    uint64_t GetSupportedFeatures() const override { return FEATURE_SUPPORTS_EDITIONS; }
    google::protobuf::Edition GetMinimumEdition() const override {
        return google::protobuf::Edition::EDITION_2023;
    }
    google::protobuf::Edition GetMaximumEdition() const override {
        return google::protobuf::Edition::EDITION_2024;
    }

    bool Generate(const google::protobuf::FileDescriptor* file, const std::string&,
                  google::protobuf::compiler::GeneratorContext* context,
                  std::string* error) const override {
        if (file->service_count() == 0) {
            return true;
        }
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                if (method->client_streaming()) {
                    *error =
                        "client-streaming and bidirectional-streaming methods are unsupported: " +
                        CopyString(method->full_name());
                    return false;
                }
                if (method->input_type()->name() == "Payload" ||
                    method->output_type()->name() == "Payload") {
                    *error = "legacy Payload is forbidden: " + CopyString(method->full_name());
                    return false;
                }
            }
        }

        std::unique_ptr<google::protobuf::io::ZeroCopyOutputStream> header(
            context->Open("hdl/rpc/v1/services.rpc.hpp"));
        google::protobuf::io::Printer out(header.get(), '$');
        out.Print("#pragma once\n\n#include \"hdl/rpc/v1/services.pb.h\"\n"
                  "#include \"rpc/status.hpp\"\n\n#include <cstdint>\n#include <string_view>\n\n");
        out.Print("namespace hdl::rpc {\n\nenum class Method : uint16_t {\n");
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                out.Print("  $name$,\n", "name", MethodEnumName(service, service->method(m)));
            }
        }
        out.Print("};\n\nstruct MethodMetadata {\n"
                  "  Method method;\n  std::string_view name;\n  std::string_view request_type;\n"
                  "  std::string_view response_type;\n  std::string_view handler_name;\n"
                  "  bool server_streaming;\n"
                  "};\n\ninline constexpr MethodMetadata kMethods[] = {\n");
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                const std::string path = CopyString(file->package()) + "." +
                                         CopyString(service->name()) + "/" +
                                         CopyString(method->name());
                out.Print("  {Method::$method$, \"$path$\", \"$request$\", \"$response$\", "
                          "\"Handle$method$\", $stream$},\n",
                          "method", MethodEnumName(service, method), "path", path, "request",
                          method->input_type()->full_name(), "response",
                          method->output_type()->full_name(), "stream",
                          method->server_streaming() ? "true" : "false");
            }
        }
        out.Print(
            "};\n\ninline constexpr std::string_view MethodName(Method method) {\n"
            "  for (const auto& item : kMethods) if (item.method == method) return item.name;\n"
            "  return {};\n}\n\n"
            "inline constexpr bool MethodIsServerStreaming(Method method) {\n"
            "  for (const auto& item : kMethods) if (item.method == method) return "
            "item.server_streaming;\n"
            "  return false;\n}\n\n"
            "inline bool ParseMethod(std::string_view name, Method* method) {\n"
            "  if (!method) return false;\n"
            "  for (const auto& item : kMethods) if (item.name == name) { *method = item.method; "
            "return true; }\n"
            "  return false;\n}\n\n"
            "inline bool ValidateRequestPayload(Method method, std::string_view payload) {\n"
            "  switch (method) {\n");
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                out.Print("  case Method::$method$: {\n"
                          "    $request$ request;\n"
                          "    return request.ParseFromArray(payload.data(), "
                          "static_cast<int>(payload.size()));\n"
                          "  }\n",
                          "method", MethodEnumName(service, method), "request",
                          CppType(method->input_type()));
            }
        }
        out.Print("  }\n"
                  "  return false;\n"
                  "}\n\n"
                  "enum class StreamingKind : uint8_t { Unary, ServerStreaming };\n\n"
                  "template <Method> struct MethodTraits;\n\n");

        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                const std::string enum_name = MethodEnumName(service, method);
                const std::string path = CopyString(file->package()) + "." +
                                         CopyString(service->name()) + "/" +
                                         CopyString(method->name());
                out.Print("template <> struct MethodTraits<Method::$method$> {\n"
                          "  using Request = $request$;\n  using Response = $response$;\n"
                          "  static constexpr std::string_view kPath = \"$path$\";\n"
                          "  static constexpr StreamingKind kStreamingKind = $stream_kind$;\n"
                          "  static constexpr bool kServerStreaming = $stream$;\n};\n\n",
                          "method", enum_name, "request", CppType(method->input_type()), "response",
                          CppType(method->output_type()), "path", path, "stream_kind",
                          method->server_streaming() ? "StreamingKind::ServerStreaming"
                                                     : "StreamingKind::Unary",
                          "stream", method->server_streaming() ? "true" : "false");
            }
        }

        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            out.Print("class $service$Client {\n public:\n"
                      "  explicit $service$Client(ClientChannel* channel) : channel_(channel) {}\n",
                      "service", service->name());
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                const std::string enum_name = MethodEnumName(service, method);
                if (method->server_streaming()) {
                    out.Print("  Status $name$(const $request$& request, "
                              "StreamCallback<$response$> callback, "
                              "CallOptions options = {}) {\n"
                              "    return InvokeServerStream<$response$>(channel_, "
                              "MethodTraits<Method::$method$>::kPath, "
                              "request, std::move(callback), options);\n  }\n",
                              "name", method->name(), "request", CppType(method->input_type()),
                              "response", CppType(method->output_type()), "method", enum_name);
                } else {
                    out.Print("  Result<$response$> $name$(const $request$& request, CallOptions "
                              "options = {}) {\n"
                              "    return InvokeUnary<$response$>(channel_, "
                              "MethodTraits<Method::$method$>::kPath, request, options);\n"
                              "  }\n",
                              "response", CppType(method->output_type()), "name", method->name(),
                              "request", CppType(method->input_type()), "method", enum_name);
                }
            }
            out.Print(" private:\n  ClientChannel* channel_;\n};\n\n");
        }
        out.Print("} // namespace hdl::rpc\n\nnamespace hdl::ipc {\n\n");
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                const std::string handler_name = MethodEnumName(service, method);
                if (method->server_streaming()) {
                    out.Print("rpc::Status Handle$name$(rpc::CallContext&, const $request$&, "
                              "rpc::ServerWriter<$response$>&);\n",
                              "name", handler_name, "request", CppType(method->input_type()),
                              "response", CppType(method->output_type()));
                } else {
                    out.Print("rpc::Status Handle$name$(rpc::CallContext&, const $request$&, "
                              "$response$*);\n",
                              "name", handler_name, "request", CppType(method->input_type()),
                              "response", CppType(method->output_type()));
                }
            }
        }
        out.Print("\n} // namespace hdl::ipc\n");

        std::unique_ptr<google::protobuf::io::ZeroCopyOutputStream> dispatch(
            context->Open("hdl/rpc/v1/services.rpc.dispatch.inc"));
        google::protobuf::io::Printer inc(dispatch.get(), '$');
        inc.Print("/* Generated by hdl_rpc_codegen. Define HDL_RPC_UNARY and HDL_RPC_STREAM. */\n");
        for (int s = 0; s < file->service_count(); ++s) {
            const auto* service = file->service(s);
            for (int m = 0; m < service->method_count(); ++m) {
                const auto* method = service->method(m);
                inc.Print(method->server_streaming()
                              ? "HDL_RPC_STREAM($method$, $name$, $request$, $response$)\n"
                              : "HDL_RPC_UNARY($method$, $name$, $request$, $response$)\n",
                          "method", MethodEnumName(service, method), "name",
                          MethodEnumName(service, method), "request", CppType(method->input_type()),
                          "response", CppType(method->output_type()));
            }
        }
        std::unique_ptr<google::protobuf::io::ZeroCopyOutputStream> contract(
            context->Open("hdl/rpc/v1/services.rpc.contract.json"));
        google::protobuf::io::Printer contract_out(contract.get(), '$');
        contract_out.PrintRaw(BuildContract(file));
        return true;
    }
};

} // namespace

int main(int argc, char** argv) {
    HdlRpcGenerator generator;
    return google::protobuf::compiler::PluginMain(argc, argv, &generator);
}
