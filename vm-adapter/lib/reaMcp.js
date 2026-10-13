// REA MCP client — PHASE 2 STUB. Nothing in the adapter calls this yet.
//
// The MVP adapter is standalone: fingerprint and jsBundle are implemented with
// Node built-ins only. When phase 2 starts, this module becomes a stdio MCP
// client to the REA server so the heavy categories (Electron/ASAR, binary via
// Ghidra, APK) can be dispatched to REA's tools.
//
// The stub exists so the shape of the integration point is fixed now: it
// answers {ok:false, reason} like every other failure in this codebase, and a
// category that reaches it degrades to a limitation instead of throwing.

export const REA_MCP_ENABLED = false;

// Tools phase 2 expects to expose. Kept as data, not code, so the categories
// the adapter advertises and the tools it can actually dispatch stay in view.
export const REA_TOOLS = [
  'asar.extract',
  'ghidra.analyzeHeadless',
  'apktool.decode',
];

// Dispatch one REA tool. Always fails in the MVP — see phase 2 checklist in
// DOCUMENT/PLAN.md before giving this a real implementation.
export async function callReaTool(_tool, _args) {
  return { ok: false, reason: 'rea mcp integration is not available (phase 2)' };
}
