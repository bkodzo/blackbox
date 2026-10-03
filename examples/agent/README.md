# Demo agent

A small agent for trying blackbox. It gives the model three read-only tools
(`list_dir`, `read_file`, `get_time`) that cannot read outside one directory,
and works with any server that accepts chat-shaped requests: a `messages`
array in, a `choices` array out.

## Run it through blackbox

Start a model server of your choice, then:

```
blackbox init
blackbox serve --upstream http://127.0.0.1:PORT --risk examples/risk.json

go run ./examples/agent -model MODEL_NAME -dir docs "Summarize the files in this folder"
```

Then look at what was recorded:

```
blackbox sessions
blackbox show demo-1a2b3c4d
blackbox verify
```

## See an anomaly get flagged

`-forge` makes the agent slip a tool result into the conversation that the
model never asked for, the way a compromised agent or a prompt injection might.
blackbox records it as `orphan_tool_result`:

```
go run ./examples/agent -model MODEL_NAME -forge "What time is it?"
```

Some servers reject the forged message outright. The rejected call is still
recorded, with the anomaly.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-url` | `http://127.0.0.1:8080/v1/chat/completions` | Endpoint to call, normally the blackbox gateway |
| `-model` | required | Model name to request |
| `-dir` | `.` | Directory the tools may read |
| `-session` | random | Session ID sent to blackbox |
| `-agent` | `demo-agent` | Agent name sent to blackbox |
| `-max-turns` | `8` | Stop after this many model calls |
| `-forge` | off | Add an unrequested tool result after the first tool call |

If the server needs an API key, set `AGENT_API_KEY`.
