// Package record defines the audit records written to the ledger.
package record

import "time"

// Record types.
const (
	TypeLLMCall      = "llm_call"
	TypeGatewayStart = "gateway_start"
	TypeGatewayStop  = "gateway_stop"
)

// GatewayStart is written when the gateway starts. Every LLMCall carries the
// InstanceID of the gateway_start that precedes it.
type GatewayStart struct {
	Type             string    `json:"type"`
	Time             time.Time `json:"ts"`
	InstanceID       string    `json:"instance_id"`
	Version          string    `json:"version"`
	ConfigSHA256     string    `json:"config_sha256"`
	KeyFingerprint   string    `json:"key_fingerprint"`
	Upstream         string    `json:"upstream"`
	PreviousShutdown string    `json:"previous_shutdown"` // "none", "clean" or "unclean"

	// Set when the log ended without a newline at startup. A complete entry
	// is kept (RepairedSeq); anything else is moved to QuarantineFile.
	RepairedSeq      uint64 `json:"repaired_seq,omitempty"`
	QuarantinedBytes int64  `json:"quarantined_bytes,omitempty"`
	QuarantineFile   string `json:"quarantine_file,omitempty"`
	QuarantineSHA256 string `json:"quarantine_sha256,omitempty"`
}

// GatewayStop is written on clean shutdown.
type GatewayStop struct {
	Type       string    `json:"type"`
	Time       time.Time `json:"ts"`
	InstanceID string    `json:"instance_id"`
	Calls      uint64    `json:"calls"`
	// Unrecorded counts calls this run forwarded but could not record.
	Unrecorded uint64 `json:"unrecorded,omitempty"`
	// AbortedAtShutdown counts calls still in flight when the shutdown grace
	// period ended; they were cancelled and recorded as aborted.
	AbortedAtShutdown uint64 `json:"aborted_at_shutdown,omitempty"`
}

// LLMCall is one exchange between an agent and the model server.
type LLMCall struct {
	Type       string `json:"type"`
	InstanceID string `json:"instance_id"`
	Format     string `json:"format"` // wire format detected by shape, or "unknown"

	// Who
	Agent        Agent   `json:"agent,omitzero"`
	Session      Session `json:"session,omitzero"`
	Principal    string  `json:"principal,omitempty"`
	CredentialFP string  `json:"credential_fp,omitempty"`
	Client       Client  `json:"client"`
	Identity     string  `json:"identity"` // "self_declared" until verified identities exist

	// Why
	Trace         Trace            `json:"trace"`
	Turn          int              `json:"turn,omitempty"`
	ToolResultsIn []ToolResultLink `json:"tool_results_in,omitempty"`
	Anomalies     []Anomaly        `json:"anomalies,omitempty"`

	// What, where, and what happened
	Request  Request  `json:"request"`
	Upstream Upstream `json:"upstream"`
	Response Response `json:"response"`
	Error    *Error   `json:"error,omitempty"`
	Timing   Timing   `json:"timing"`
}

type Agent struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

type Session struct {
	ID       string `json:"id,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	// Conversation identifies calls without a session ID that continue the
	// same conversation: a hash of its opening messages.
	Conversation string `json:"conversation,omitempty"`
}

type Client struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent,omitempty"`
}

type Trace struct {
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id,omitempty"`
}

// ToolResultLink ties a tool result the agent sent back to the call where
// the model requested it.
type ToolResultLink struct {
	ToolCallID string `json:"tool_call_id"`
	MatchedSeq uint64 `json:"matched_seq,omitempty"` // 0 when no request was found
}

type Anomaly struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type Request struct {
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	ModelRequested string   `json:"model_requested,omitempty"`
	Stream         bool     `json:"stream,omitempty"`
	MessageCount   int      `json:"message_count,omitempty"`
	SystemSHA256   string   `json:"system_sha256,omitempty"`
	ToolsOffered   []string `json:"tools_offered,omitempty"`
	ToolsSHA256    string   `json:"tools_sha256,omitempty"`
	Body           Body     `json:"body"`
}

type Upstream struct {
	URL               string `json:"url"`
	ModelServed       string `json:"model_served,omitempty"`
	RequestID         string `json:"request_id,omitempty"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
}

type Response struct {
	Status       int        `json:"status"`
	ContentType  string     `json:"content_type,omitempty"`
	FinishReason string     `json:"finish_reason,omitempty"`
	ToolCalls    []ToolCall `json:"tool_calls,omitempty"`
	Usage        Usage      `json:"usage,omitzero"`
	Stream       *Stream    `json:"stream,omitempty"`
	// Reasoning summarizes the model's reasoning, when the server returned it.
	Reasoning *Reasoning `json:"reasoning,omitempty"`
	// IgnoredTextCalls counts tool-call-shaped JSON in the reply text that was
	// not counted as a call: it named a tool that was not offered and is not
	// in the risk map.
	IgnoredTextCalls int `json:"ignored_text_calls,omitempty"`
	// TextScanPartial is set when the reply text was too long or complex to
	// search completely for tool calls written as text.
	TextScanPartial bool `json:"text_scan_partial,omitempty"`
	// Upgraded is set when the server switched protocols (status 101).
	// Traffic after the switch is passed through but not recorded.
	Upgraded bool `json:"upgraded,omitempty"`
	Body     Body `json:"body"`
}

type ToolCall struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments,omitempty"`
	ValidJSON bool   `json:"arguments_valid_json"`
	InText    bool   `json:"in_text,omitempty"` // written in the reply text, not made as a structured call
	Risk      string `json:"risk,omitempty"`
	Category  string `json:"category,omitempty"`
}

// Reasoning summarizes the reasoning a model returned with its reply. The
// full text is in the response body; this holds what a reviewer needs at a
// glance without storing it twice.
type Reasoning struct {
	Preview        string `json:"preview,omitempty"` // the first ReasoningPreview characters
	Chars          int    `json:"chars"`
	SHA256         string `json:"sha256,omitempty"`
	RedactedBlocks int    `json:"redacted_blocks,omitempty"` // returned only in encrypted form
}

// ReasoningPreview is how many characters of reasoning a record keeps.
const ReasoningPreview = 500

type Usage struct {
	Input  int `json:"input,omitempty"`
	Output int `json:"output,omitempty"`
	Total  int `json:"total,omitempty"`
}

// Stream outcomes.
const (
	StreamCompleted     = "completed"
	StreamClientAborted = "client_aborted"
	StreamUpstreamError = "upstream_error"
)

type Stream struct {
	Chunks  int    `json:"chunks"`
	Outcome string `json:"outcome"`
}

// Error classes.
const (
	ErrorUpstreamUnreachable = "upstream_unreachable"
	ErrorUpstreamStatus      = "upstream_status"
	ErrorUpstreamRead        = "upstream_read"
	ErrorClientAborted       = "client_aborted"
	ErrorGatewayShutdown     = "gateway_shutdown"
	ErrorRequestTooLarge     = "request_too_large"
	ErrorGatewayBusy         = "gateway_busy"
)

type Error struct {
	Class   string `json:"class"` // see the Error* constants
	Message string `json:"message"`
}

type Timing struct {
	ReceivedAt     time.Time `json:"received_at"`
	UpstreamSentAt time.Time `json:"upstream_sent_at,omitzero"`
	FirstByteAt    time.Time `json:"first_byte_at,omitzero"`
	CompletedAt    time.Time `json:"completed_at"`
}

// Body holds the exact bytes exchanged. Text is stored verbatim so SHA256
// can be recomputed from the log; non-UTF-8 bytes are stored as base64.
// Bytes may exceed len(Text) when capture was capped (Truncated).
type Body struct {
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Text      string `json:"text,omitempty"`
	Base64    string `json:"base64,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Anomaly kinds.
const (
	AnomalyOrphanToolResult    = "orphan_tool_result"
	AnomalyHistoryRewritten    = "history_rewritten"
	AnomalyHistoryTruncated    = "history_truncated"
	AnomalyToolsetChanged      = "toolset_changed"
	AnomalySystemPromptChanged = "system_prompt_changed"
	AnomalyModelSubstituted    = "model_substituted"
	AnomalyStreamAborted       = "stream_aborted"
	AnomalyHighRiskTool        = "high_risk_tool"
	AnomalyToolCallInText      = "tool_call_in_text"
	AnomalyUnverifiableResult  = "unverifiable_tool_result"
	AnomalyDuplicateToolResult = "duplicate_tool_result"
	AnomalyTextCallExecuted    = "text_tool_call_executed"
	AnomalyTextScanPartial     = "text_scan_partial"
)

// Exchange is one finished request and response as captured by the proxy,
// before the payloads are parsed. Call holds every field known without
// parsing; Req and Resp hold the stored bodies.
type Exchange struct {
	Call      *LLMCall
	Req, Resp []byte
	SSE       bool
}

// Size is the memory held by the exchange's bodies.
func (x Exchange) Size() int64 { return int64(len(x.Req) + len(x.Resp)) }
