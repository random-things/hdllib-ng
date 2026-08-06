# Named-pipe RPC protocol

`hdllib`'s remote protocol is `hdl.rpc.v1`: protobuf-Lite messages carried over a local Windows named pipe. The protobuf schema is the complete remote contract; clients do not need C++ structure layouts or a separate operation-number registry.

## Schema and generated bindings

The source of truth is [`proto/hdl/rpc/v1`](../proto/hdl/rpc/v1):

- `common.proto` defines `RpcStatus`, transport limits, method metadata, and shared `Empty`.
- `envelope.proto` defines negotiation, requests, responses, and connection shutdown.
- `types.proto` defines domain messages shared by services.
- The per-service files define method request, response, and batch messages.
- `services.proto` is the authoritative inventory of the 12 services, 97 methods, and their streaming declarations.
- `contract.json` is the descriptor-derived compatibility golden. It records services, methods, streaming flags, message fields and numbers, and enum values.

CMake pins the host-side Protobuf compiler and Lite runtime. `hdl_rpc_codegen`, a host-side protoc plugin, generates service-qualified method identifiers, `MethodTraits`, method metadata, typed client stubs, `Handle<Service>_<Method>` declarations, server dispatch, and the contract manifest. Generation rejects client-streaming, bidirectional-streaming, or any service method that uses the removed legacy `Payload` type.

## Connection sequence

1. The client opens `HdlFormatPipeName(pid)` and writes the eight-byte `HDLRPC1\n` preface.
2. It writes a length-prefixed `Envelope.client_hello` with protocol `1.0`.
3. The server replies with `Envelope.server_hello`, including its method inventory, transport limits, and a random 128-bit instance ID stable for the loaded server lifetime. A different major version is rejected; the minor version is reserved for additive evolution.
4. The client serializes the method's declared request message directly into `Request.payload`. `Request.method` is its generated fully qualified path, for example `hdl.rpc.v1.Memory/ReadMemory`.
5. The server parses that declared request type and emits responses whose payloads directly contain the declared response or stream-batch type.

Every post-preface message is framed as a little-endian `uint32_t` byte count followed by that many serialized `Envelope` bytes. Frames are capped at 64 MiB before allocation. The negotiated limits currently permit one active request per connection and a 1 MiB serialized stream message; independent connections remain concurrent.

The reusable channel is [`src/rpc/pipe_client.cpp`](../src/rpc/pipe_client.cpp).
It validates the negotiated inventory, request ID, sequence, terminal framing,
and typed payload before returning through generated clients. Both `hdlclient`
and the local unload path use this implementation.

## Envelope responsibilities

The envelope contains transport and protocol metadata only:

- `Request`: nonzero request ID, fully qualified method path, deadline as `timeout_ms`, and serialized typed request bytes.
- `Response`: matching request ID, monotonically increasing sequence, `end_stream`, authoritative `RpcStatus`, and optional serialized typed response bytes.
- `GoAway`: connection-level failure status for handshake, framing, or envelope violations when it can still be delivered.

`Request.timeout_ms == 0` means no caller deadline. Method streaming behavior comes exclusively from `services.proto`; callers do not select an alternate delivery mode.

## Unary and streaming responses

A unary call produces exactly one response with sequence `0` and `end_stream=true`. Its payload is the declared response message when a response is present. A non-OK unary response may still include a typed partial result when the domain operation meaningfully reports partial bytes, counts, or call copy-outs.

A server-streaming call produces zero or more typed data responses with `end_stream=false`, followed by one terminal response with no payload and `end_stream=true`. Data responses have `OK` status. The terminal response carries the final status. The sequence starts at zero and increments for every response, including the terminal response.

Streaming writes are synchronous and bounded, providing named-pipe backpressure. If a caller stops its callback early, the client closes the pipe; the server observes the failed write and stops the operation. Search batches contain at most 4096 addresses and are further bounded by the negotiated stream-message limit.

## Status and failures

`RpcStatus` is authoritative. It contains an RPC-layer `RpcCode`, a stable machine-readable `reason`, a diagnostic `message`, the corresponding `HdlStatusCode`, and `outcome_unknown` for a timeout or cancellation where an in-process call may still be running.

- Framing, handshake, or envelope violations send `GoAway` when possible and then close the connection.
- An unknown method returns terminal `UNIMPLEMENTED`.
- A malformed method payload or invalid field returns terminal `INVALID_ARGUMENT`.
- Domain failures are mapped to `RpcStatus`, optionally with a meaningful typed partial response.
- A broken stream write or caller-aborted callback closes the connection.

## Deadlines and large searches

Search methods intentionally have no default deadline: a broad or low-selectivity query can legitimately run for a long time. A result limit of zero means unlimited. `hdlclient scan` writes unlimited result streams to a controller-owned candidate file (or a caller-selected `--candidates FILE`) and keeps only a 64-address preview in memory. The file starts with `HDLCAND1`, a little-endian version (`1`), record size (`8`), 64-bit record count, and then contiguous 64-bit addresses.

With one active request per connection, abandoning a response closes that connection. Cooperative envelope deadlines bound work that does not emit intermediate responses. The Windows client enforces the same absolute deadline across all request writes and response reads with completion-port-driven overlapped named-pipe I/O; expiration cancels the pending operation and closes the connection. Remote call methods derive their execution timeout from the envelope deadline; no inner timeout or job identifier exists on the wire.

## Evolution rules

- Method identity, input/output types, and streaming behavior come only from the protobuf service schema.
- New fields use new field numbers; removed field numbers are reserved and existing meanings are never reused.
- Additive compatible methods and fields may remain in `hdl.rpc.v1`.
- An incompatible change requires a new package/protocol major, not an update that merely accepts a changed golden contract.
- There is no legacy opcode, positional-payload, or mixed-contract compatibility mode.

Schema, message-conversion, and live transport tests cover the fixed inventory,
service-qualified handler names, malformed payloads, unknown methods, frame
limits, partial unary results, stream termination, connection concurrency, and
the one-active-call channel rule.
