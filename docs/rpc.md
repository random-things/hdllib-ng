# Named-pipe RPC protocol

`hdllib`'s first supported remote protocol is `hdl.rpc.v1`. It is a protobuf-Lite protocol over a local Windows named pipe; numeric operation codes are not part of the contract.

## Schema and generation

The source of truth is [`proto/hdl/rpc/v1`](../proto/hdl/rpc/v1):

- `common.proto` defines status, method metadata, transport limits, and the payload adapter.
- `envelope.proto` defines negotiation, requests, responses, and connection shutdown.
- `services.proto` declares the domain services and their named methods.

CMake pins the host-side Protobuf compiler and Lite runtime. `hdl_rpc_codegen`, a protoc plugin built only for the host toolchain, derives the C++ method enum, method-name parser, metadata table, and dispatch include from `services.proto`. Adding or removing an RPC therefore changes the schema; there is no separate operation-number or dispatch manifest to synchronize.

## Connection sequence

1. The client opens `HdlFormatPipeName(pid)` and writes the eight-byte `HDLRPC1\n` preface.
2. It writes a length-prefixed `Envelope.client_hello` with protocol `1.0`.
3. The server replies with `Envelope.server_hello`, including a random 128-bit instance ID that is stable for the loaded server lifetime. A different major version is rejected; the minor version is informational for additive evolution.
4. The client sends `Envelope.request` messages. `Request.method` is the generated fully qualified name, for example `hdl.rpc.v1.Search/SearchMemory`.
5. The server emits one or more `Envelope.response` messages with the same nonzero request ID. `end_stream` marks the final response.

Every post-preface message is framed as a little-endian `uint32_t` byte count followed by that many serialized protobuf bytes. The first release permits one active request per pipe connection and advertises limits of 64 MiB per frame and 1 MiB per stream chunk. Independent pipe connections remain concurrent. Streaming eligibility is generated from `services.proto`; `Request.stream_response` asks an eligible method for incremental delivery instead of its aggregate payload-adapter form.

## Deadlines and large searches

`Request.timeout_ms == 0` means no caller deadline. Search methods intentionally advertise no default deadline: a broad or low-selectivity query can legitimately run for a very long time. Callers may set an explicit deadline when they prefer bounded work.

Search results are streamed with bounded chunks and backpressure. A result limit of zero means unlimited; clients must not translate it into a small timeout. `hdlclient scan` writes unlimited result streams to a controller-owned candidate file (or a caller-selected `--candidates FILE`) and keeps only a 64-address preview in memory. The binary file starts with `HDLCAND1`, a little-endian version (`1`), record size (`8`), 64-bit record count, and then contiguous 64-bit addresses.

With one active request per connection, a client that abandons a response closes
that pipe. Streaming handlers observe the broken write at the next bounded chunk
and stop producing results. Cooperative `Request.timeout_ms` remains the way to
bound work that does not emit intermediate responses.

## Evolution rules

- Method identity comes only from the protobuf service schema.
- New fields use new field numbers; existing field meanings are not reused.
- New methods are additive within `hdl.rpc.v1` when old peers can safely ignore their absence.
- A wire-incompatible redesign changes the package major and connection major together.
- This is the first release contract; there is no legacy opcode handshake or compatibility mode.
