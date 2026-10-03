# blackbox

blackbox is an audit gateway for AI agents. It sits between an agent and any
model server and records every prompt, tool call, and response in a signed,
append-only log. It does not depend on a particular model or provider.

Status: early development. The gateway, log, and CLI work; the dashboard is
in progress.

## Usage

```
go install github.com/bkodzo/blackbox/cmd/blackbox@latest

blackbox init                                   # create the signing key
blackbox serve --upstream http://127.0.0.1:9000 # point your agent at http://127.0.0.1:8080
blackbox sessions                               # list recorded agent sessions
blackbox show run-42                            # what happened in one session
blackbox verify                                 # check the log has not been altered
```

Agents can describe themselves with optional headers, which are removed before
the request is forwarded: `X-Blackbox-Session`, `X-Blackbox-Parent-Session`,
`X-Blackbox-Agent`, `X-Blackbox-Agent-Version`, and `X-Blackbox-Principal`.

## What gets flagged

| Anomaly | Meaning |
|---|---|
| `orphan_tool_result` | The agent returned a result for a tool call the model never made |
| `history_rewritten` | An earlier message, or the model's tool calls, changed between turns |
| `history_truncated` | Earlier messages were dropped |
| `toolset_changed` | The tools offered to the model changed mid-session |
| `system_prompt_changed` | The system prompt changed mid-session |
| `model_substituted` | A different model answered than the one requested |
| `stream_aborted` | The client disconnected before the response finished |
| `high_risk_tool` | The model requested a tool marked high risk in the risk map |

## How the log detects tampering

Each entry stores the hash of the previous entry and is signed with the
gateway's Ed25519 key. Signed checkpoints are written to a separate file.
Verification fails if a record is edited, deleted, reordered, or removed from
the end of the log, or if the chain is rebuilt with a different key.

## License

MIT
