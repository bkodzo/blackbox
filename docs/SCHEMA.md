# Log schema

The log is a JSON Lines file. Each line is an entry that seals one record.

## Entry

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Format version, currently 2 |
| `seq` | integer | Position in the log, starting at 1 |
| `kid` | hex string | ID of the signing key: the first 8 bytes of the SHA-256 of the public key |
| `prev` | hex string | `hash` of the previous entry; 64 zeros for the first |
| `hash` | hex string | SHA-256 of the tag `blackbox/entry/v2`, `seq`, `kid`, `prev`, and the `rec` bytes |
| `sig` | base64 string | Ed25519 signature of the tag `blackbox/entry-sig/v2` followed by `hash` |
| `rec` | object | The record (below), stored exactly as it was hashed |

Fields appear in exactly this order with no whitespace. A line that is not
byte-for-byte the encoding of its parsed fields is rejected.

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
| `repaired_seq` | Set if the last entry was complete but missing its newline; the newline was added |
| `quarantined_bytes` | Bytes of an incomplete final line moved out of the log at startup |
| `quarantine_file` | Where those bytes were saved |
| `quarantine_sha256` | Hash of those bytes |

## gateway_stop

| Field | Meaning |
|---|---|
| `ts` | Stop time (UTC) |
| `instance_id` | ID of the run that stopped |
| `calls` | Calls recorded by this run |
| `unrecorded` | Calls forwarded but not recorded (only possible in fail-open mode or at a write failure) |
| `aborted_at_shutdown` | Calls cancelled when the shutdown grace period ended; each is recorded |

## llm_call

### Who

| Field | Meaning |
|---|---|
| `agent.id`, `agent.version` | From `X-Blackbox-Agent` and `X-Blackbox-Agent-Version` |
| `session.id`, `session.parent_id` | From `X-Blackbox-Session` and `X-Blackbox-Parent-Session` |
| `session.conversation` | For calls without a session ID: a hash identifying the conversation they continue |
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
| `response.reasoning` | When the server returned the model's reasoning: `preview` (the first 500 characters), `chars`, `sha256` of the full text, and `redacted_blocks` returned only in encrypted form. The full text is in the response body |
| `response.ignored_text_calls` | Tool-call-shaped JSON in the reply text that was not counted as a call, because it named a tool that was not offered and is not in the risk map |
| `response.text_scan_partial` | True if the reply text was too long or complex to search completely for tool calls written as text |
| `response.upgraded` | True if the server switched protocols (status 101); traffic after the switch is not recorded |
| `response.body` | See Body |

`in_text` is true for a tool call the model wrote into its reply text instead of
making it. The agent may not have run it.

### Error and timing

| Field | Meaning |
|---|---|
| `error.class` | `upstream_unreachable`, `upstream_status`, `upstream_read`, `client_aborted`, `gateway_shutdown`, `request_too_large`, or `gateway_busy` |
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
| `orphan_tool_result` | A tool result answers a call the model never made in this conversation |
| `unverifiable_tool_result` | A tool result arrived with no earlier turn to check it against |
| `duplicate_tool_result` | Another result arrived for a tool call that was already answered |
| `text_tool_call_executed` | The agent ran a call the model only wrote as text |
| `text_scan_partial` | The reply text could not be searched completely for tool calls written as text |
| `history_rewritten` | An earlier message, or the model's tool calls or reply text, changed or was left out; or messages were attributed to the model that it never sent |
| `history_truncated` | Older messages were dropped since the previous turn |
| `toolset_changed` | The tools offered changed since the previous turn |
| `system_prompt_changed` | The system prompt changed since the previous turn |
| `model_substituted` | The model that answered differs from the one requested |
| `stream_aborted` | The client disconnected before the response finished |
| `high_risk_tool` | A tool marked high risk in the risk map was requested |
| `tool_call_in_text` | The model wrote a tool call into its reply text |

## Checkpoint file

One JSON object per line, in this exact form:

| Field | Meaning |
|---|---|
| `v` | Format version, currently 2 |
| `log` | Hash of entry 1, identifying the log |
| `seq` | Sequence number of the checkpointed entry |
| `hash` | Hash of that entry |
| `ts` | When the checkpoint was written (RFC 3339, UTC) |
| `kid` | ID of the signing key |
| `sig` | Ed25519 signature over the tag `blackbox/checkpoint/v2` and every field above |

## Risk map

A JSON object keyed by tool name:

```json
{ "run_shell": { "risk": "high", "category": "execute", "says": "ran a command: {cmd}" } }
```

`risk` is `low`, `medium`, or `high`. Tools not listed are recorded as
`unknown`. `says` is a plain-language description for reports.
