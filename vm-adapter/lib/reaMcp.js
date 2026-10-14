// REA integration — real implementation (phase 2).
//
// Previously a stub; now dispatches to the REA engine installed on the VM via
// lib/reaCli.js (subprocess to the `rea` CLI — the adapter stays zero-dependency).
// The integration contract is unchanged: every dispatch answers
// {ok:true, ...} | {ok:false, reason} so a category that reaches REA degrades
// to a limitation instead of throwing.
//
// Tool catalogue (dotted names, as before):
//   browser.capture  — bounded Playwright scenario: screenshot + DOM + network
//                      evidence via the REA engine (needs reaEnv prerequisites)
//   js.analyzeDeep   — REA static analysis over the page's downloaded bundles
//
// Categories the engine cannot serve on this VM (no Ghidra/IDA, no JADX/JDK)
// are answered {ok:false} with a reason naming the missing piece, so callers
// surface them as limitations.

import { captureBrowser, analyzeJsDeep } from './reaCli.js';

export const REA_MCP_ENABLED = true;

export const REA_TOOLS = [
  'browser.capture',
  'js.analyzeDeep',
];

// Dispatch one REA tool.
// args: { url, safeFetch?, timeoutMs? } — safeFetch is the adapter's guarded
// fetch, required by js.analyzeDeep for downloading bundles.
export async function callReaTool(tool, args = {}) {
  const { url, safeFetch, timeoutMs } = args;
  if (!url) return { ok: false, reason: 'callReaTool requires args.url' };

  switch (tool) {
    case 'browser.capture':
      return captureBrowser(url, { timeoutMs });
    case 'js.analyzeDeep': {
      if (typeof safeFetch !== 'function') {
        return { ok: false, reason: 'js.analyzeDeep requires args.safeFetch' };
      }
      return analyzeJsDeep(url, safeFetch, { timeoutMs });
    }
    case 'asar.extract':
    case 'ghidra.analyzeHeadless':
    case 'apktool.decode':
      return { ok: false, reason: `${tool} needs an analysis engine not installed on this VM (see docs/vm-setup.md)` };
    default:
      return { ok: false, reason: `unknown REA tool: ${tool}` };
  }
}
