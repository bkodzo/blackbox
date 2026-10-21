package dashboard

import "github.com/bkodzo/blackbox/internal/record"

// flagInfo describes an anomaly kind in plain language.
type flagInfo struct {
	Title   string
	Meaning string
	Serious bool // shown first and highlighted
}

var flagInfos = map[string]flagInfo{
	record.AnomalyOrphanToolResult:    {"Result for a call never made", "The agent returned a result for a tool call the model never made.", true},
	record.AnomalyDuplicateToolResult: {"Repeated tool result", "The agent returned another result for a call already answered.", false},
	record.AnomalyUnverifiableResult:  {"Unverifiable tool result", "A tool result arrived with no earlier turn to check it against.", false},
	record.AnomalyHistoryRewritten:    {"History rewritten", "Earlier messages, the model's calls or text, or what is attributed to the model changed between turns.", true},
	record.AnomalyHistoryTruncated:    {"History shortened", "Older messages were dropped from the conversation.", false},
	record.AnomalyToolsetChanged:      {"Tools changed", "The tools offered to the model changed mid-session.", false},
	record.AnomalySystemPromptChanged: {"Instructions changed", "The system prompt changed mid-session.", true},
	record.AnomalyModelSubstituted:    {"Different model answered", "A different model answered than the one requested.", false},
	record.AnomalyStreamAborted:       {"Response cut off", "The client disconnected before the response finished.", false},
	record.AnomalyHighRiskTool:        {"High-risk tool", "The model requested a tool marked high risk in the risk map.", true},
	record.AnomalyToolCallInText:      {"Tool call written as text", "The model wrote a tool call into its reply text instead of making one.", false},
	record.AnomalyTextCallExecuted:    {"Text tool call run", "The agent ran a call the model only wrote as text.", true},
	record.AnomalyTextScanPartial:     {"Reply not fully searched", "The reply was too long or complex to search completely for tool calls written as text.", false},
	record.AnomalyAmbiguousRequest:    {"Ambiguous request", "The request has keys that differ from expected fields only in letter case, so the model server may read it differently.", true},
	record.AnomalyRequestTooComplex:   {"Request not checked", "The request had too many JSON values to parse, so it was recorded but not checked.", true},
}

// flag returns the description of an anomaly kind, falling back to the kind.
func flag(kind string) flagInfo {
	if f, ok := flagInfos[kind]; ok {
		return f
	}
	return flagInfo{Title: kind, Meaning: "An anomaly this version of the dashboard does not describe."}
}

var errorTitles = map[string]string{
	record.ErrorUpstreamUnreachable: "model server unreachable",
	record.ErrorUpstreamStatus:      "model server returned an error",
	record.ErrorUpstreamRead:        "response could not be read",
	record.ErrorClientAborted:       "agent disconnected",
	record.ErrorGatewayShutdown:     "cancelled at gateway shutdown",
	record.ErrorRequestTooLarge:     "request too large",
	record.ErrorUpgradeRefused:      "protocol upgrade refused",
	record.ErrorStreamIdle:          "response stalled",
}

func errorTitle(class string) string {
	if t, ok := errorTitles[class]; ok {
		return t
	}
	return class
}
