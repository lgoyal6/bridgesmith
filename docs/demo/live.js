/* Clear stale output on input edits, aborts, timeouts and failed requests. */
"use strict";
const byId = (id) => document.getElementById(id);
let generation = 0;
let pending;
function clearResult(message) {
  byId("run-status").textContent = message;
  byId("run-badge").textContent = "WAITING";
  byId("run-badge").className = "result-pill";
  byId("timeline").replaceChildren();
  byId("call-output").hidden = true;
  byId("call-output").textContent = "";
  byId("proof").hidden = true;
  byId("proof-output").textContent = "";
  byId("call-summary").textContent = "Only a mounted connector can call the catalog. Invalid data is withheld.";
}
byId("lab-form").addEventListener("input", () => {
  generation++;
  pending?.abort();
  clearResult("Inputs changed. Run again to see a result.");
  byId("run-button").disabled = false;
  byId("results").setAttribute("aria-busy", "false");
});
byId("lab-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const current = ++generation;
  pending?.abort();
  const controller = new AbortController();
  pending = controller;
  const timeout = setTimeout(() => controller.abort(), 15000);
  clearResult("Running certification and connector gates...");
  byId("run-button").disabled = true;
  byId("results").setAttribute("aria-busy", "true");
  const input = {
    count: Number(byId("count").value), seed: Number(byId("seed").value), query: byId("query").value,
    fault: byId("fault").value, faultAt: byId("faultAt").value, trust: byId("trust").value,
  };
  try {
    const response = await fetch("/api/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input), signal: controller.signal });
    const result = await response.json();
    if (current !== generation) return;
    if (!response.ok) throw new Error(result.error || "No connector result is available.");
    const passed = result.call?.ok === true;
    byId("run-status").textContent = passed ? "Connector read completed" : result.mounted ? "Response rejected by the runtime" : "Connector mounting refused";
    byId("run-badge").textContent = passed ? "VALIDATED" : "REJECTED";
    byId("run-badge").className = `result-pill ${passed ? "" : "rejected"}`;
    for (const entry of result.timeline) {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = `${entry.pass ? "PASS" : "REFUSE"} / ${entry.stage}`;
      const detail = document.createElement("span");
      detail.textContent = entry.detail;
      item.append(title, detail);
      byId("timeline").append(item);
    }
    byId("call-summary").textContent = `${result.serviceCalls} in-process catalog read(s). ${result.call ? `Runtime outcome: ${result.call.outcome}.` : "No adapter call occurred."} ${result.trust?.clockAdvanced ? "Expiry evaluated with an advanced clock." : ""}`;
    if (result.call) {
      byId("call-output").textContent = JSON.stringify(result.call.ok ? result.call.data : { outcome: result.call.outcome, error: result.call.error, data: "withheld" }, null, 2);
      byId("call-output").hidden = false;
    }
    byId("proof-output").textContent = JSON.stringify({ input: result.input, trust: result.trust, certificate: result.certificate, report: result.report, reached: result.reached }, null, 2);
    byId("proof").hidden = false;
  } catch (error) {
    if (current !== generation) return;
    clearResult(error.name === "AbortError" ? "Run timed out. No result is available." : error.message);
    byId("run-badge").textContent = "ERROR";
  } finally {
    clearTimeout(timeout);
    if (current === generation) {
      byId("run-button").disabled = false;
      byId("results").setAttribute("aria-busy", "false");
    }
  }
});
