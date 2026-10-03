# Log schema

The log is a JSON Lines file. Each line is an entry that seals one record.

## Entry

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | Position in the log, starting at 1 |
| `prev` | hex string | `hash` of the previous entry; 64 zeros for the first |
| `hash` | hex string | SHA-256 of `seq` (8 bytes, big-endian), `prev`, and the `rec` bytes |
| `sig` | base64 string | Ed25519 signature of `hash` by the gateway key |
| `rec` | object | The record (below) |

Every record has a `type` field: `gateway_start`, `gateway_stop`, or `llm_call`.

## gateway_start

| Field | Meaning |
|---|---|
| `ts` | Start time (UTC) |
| `instance_id` | Random ID for this run; every `llm_call` carries it |
| `version` | blackbox version |
| `config_sha256` | Hash of the effective configuration and the risk map contents |
| `key_fingerprint` | Fingerprint of the signing key |
| `upstream` | Model server URL |
| `previous_shutdown` | `none` (new log), `clean`, or `unclean` |
| `recovered_torn_bytes` | Bytes of an incomplete final line removed at startup, if any |

## gateway_stop

| Field | Meaning |
|---|---|
| `ts` | Stop time (UTC) |
| `instance_id` | ID of the run that stopped |
| `calls` | Calls recorded by this run |

## llm_call

### Who

| Field | Meaning |
|---|---|
| `agent.id`, `agent.version` | From `X-Blackbox-Agent` and `X-Blackbox-Agent-Version` |
| `session.id`, `session.parent_id` | From `X-Blackbox-Session` and `X-Blackbox-Parent-Session` |
| `principal` | From `X-Blackbox-Principal`: the person or service the agent acts for |
| `credential_fp` | `sha256:` and the first 8 bytes of the hash of the API key. The key is never stored |
| `client.ip`, `client.user_agent` | Where the call came from |
| `identity` | `self_declared`: the fields above come from the caller |

### Why

| Field | Meaning |
|---|---|
| `trace.trace_id`, `trace.span_id`, `trace.parent_span_id` | W3C trace context, continued from `traceparent` if sent |
| `turn` | Position of the call in its session |
| `tool_results_in[]` | New tool results in this request: `tool_call_id`, and `matched_seq`, the entry where the model requested it (0 if never) |
| `anomalies[]` | `kind` and a plain-language `detail` |

### Request

| Field | Meaning |
|---|---|
| `request.method`, `request.path` | HTTP method and path |
| `request.model_requested` | Model named in the request |
| `request.stream` | Whether a streamed response was requested |
| `request.message_count` | Messages in the request |
| `request.system_sha256` | Hash of the system prompt |
| `request.tools_offered[]`, `request.tools_sha256` | Tool names offered, and a hash of their full definitions |
| `request.body` | See Body |

### Upstream

| Field | Meaning |
|---|---|
| `upstream.url` | Model server URL |
| `upstream.model_served` | Model named in the response |
| `upstream.request_id` | The server's request ID header, if any |
| `upstream.system_fingerprint` | The server's fingerprint field, if any |

### Response

| Field | Meaning |
|---|---|
| `response.status` | HTTP status |
| `response.content_type` | Response content type |
| `response.finish_reason` | Why generation stopped, as reported by the server |
| `response.tool_calls[]` | `id`, `name`, `arguments`, `arguments_valid_json`, `in_text`, `risk`, `category` |
| `response.usage` | `input`, `output`, and `total` tokens |
| `response.stream` | For streamed responses: `chunks` and `outcome` (`completed`, `client_aborted`, `upstream_error`) |
| `response.body` | See Body |

`in_text` is true for a tool call the model wrote into its reply text instead of
making it. The agent may not have run it.

### Error and timing

| Field | Meaning |
|---|---|
| `error.class` | `upstream_unreachable`, `upstream_status`, `upstream_read`, or `client_aborted` |
| `error.message` | Detail |
| `timing.received_at` | Request received by the gateway |
| `timing.upstream_sent_at` | Request sent to the model server |
| `timing.first_byte_at` | First response byte received |
| `timing.completed_at` | Exchange finished |

All times are RFC 3339 in UTC.

### Other

| Field | Meaning |
|---|---|
| `instance_id` | The `gateway_start` run that wrote this call |
| `format` | Detected payload shape: `chat`, `blocks`, or `unknown` |

## Body

| Field | Meaning |
|---|---|
| `sha256` | Hash of every byte exchanged |
| `bytes` | Number of bytes exchanged |
| `text` | The bytes, verbatim, if valid UTF-8 |
| `base64` | The bytes, base64-encoded, otherwise |
| `truncated` | True if only the first 32 MiB (configurable) were stored |

## Anomaly kinds

| Kind | Meaning |
|---|---|
| `orphan_tool_result` | A tool result answers a call the model never made in this session |
| `history_rewritten` | An earlier message, or the model's tool calls, changed between turns |
| `history_truncated` | The request has fewer messages than the previous turn |
| `toolset_changed` | The tools offered changed since the previous turn |
| `system_prompt_changed` | The system prompt changed since the previous turn |
| `model_substituted` | The model that answered differs from the one requested |
| `stream_aborted` | The client disconnected before the response finished |
| `high_risk_tool` | A tool marked high risk in the risk map was requested |
| `tool_call_in_text` | The model wrote a tool call into its reply text |

## Checkpoint file

One JSON object per line: `seq`, `hash`, and `sig` of the newest durable entry
at the time, and `ts`. The signature is the entry's own.

## Risk map

A JSON object keyed by tool name:

```json
{ "run_shell": { "risk": "high", "category": "execute", "says": "ran a command: {cmd}" } }
```

`risk` is `low`, `medium`, or `high`. Tools not listed are recorded as
`unknown`. `says` is a plain-language description for reports.
