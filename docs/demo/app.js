/*
 * Render a saved connector certificate, report, and schema.
 * evidence.json pins the copied repository artifacts by SHA256.
 * This page checks file integrity; it does not validate a registry trust root.
 */
(async function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const evidence = await fetch("evidence.json").then((response) => {
    if (!response.ok) throw new Error("The evidence index could not be loaded.");
    return response.json();
  }).catch((error) => {
    document.querySelector("main").textContent = error.message;
    return null;
  });
  if (!evidence) return;

  const artifact = evidence.artifact;
  const operation = artifact.operation;
  const mutation = artifact.mutationStats;
  const holdout = artifact.checks.find((row) => row.check === "holdout-replay");
  const mutationCheck = artifact.checks.find((row) => row.check === "mutation");

  $("artifact-title").textContent = `${artifact.app} · certificate v${artifact.version}`;
  $("artifact-result").textContent = artifact.certifiedOps.length ? "CERTIFIED IN SAVED REPORT" : "NOT CERTIFIED";
  $("certified-count").textContent = artifact.certifiedOps.length;
  $("holdout-count").textContent = holdout ? holdout.detail.match(/\d+/)?.[0] ?? "-" : "-";
  $("mutation-count").textContent = `${mutation.caught}/${mutation.generated}`;
  $("missed-count").textContent = mutation.missed;
  $("holdout-detail").textContent = holdout?.detail ?? "No holdout result is recorded.";
  $("mutation-detail").textContent = mutationCheck?.detail ?? "No mutation result is recorded.";
  $("signature-detail").textContent = `${artifact.signatureAlgorithm} signature, issued ${artifact.issuedAt.slice(0, 10)}`;
  $("operation-method").textContent = operation.method;
  $("operation-id").textContent = operation.id;
  $("operation-path").textContent = operation.path;
  $("operation-fields").textContent = `Query: ${operation.queryParams.join(", ")} · Response fields: ${operation.responseFields.join(", ")}`;
  $("source-commit").textContent = `Source ${evidence.sourceCommit.slice(0, 12)}`;
  $("source-link").href = `https://github.com/lgoyal6/bridgesmith/tree/${encodeURIComponent(evidence.sourceCommit)}/connectors/devpost/v1`;

  const checkList = $("check-list");
  for (const row of artifact.checks) {
    const item = document.createElement("li");
    const icon = document.createElement("span");
    icon.className = row.pass ? "check-icon" : "limit-icon";
    icon.textContent = row.pass ? "✓" : "!";
    const text = document.createElement("span");
    text.textContent = `${row.op}: ${row.detail}`;
    item.append(icon, text);
    checkList.append(item);
  }

  const limitsList = $("limits-list");
  for (const sentence of evidence.limits) {
    const item = document.createElement("li");
    const icon = document.createElement("span");
    icon.className = "limit-icon";
    icon.textContent = "i";
    const text = document.createElement("span");
    text.textContent = sentence;
    item.append(icon, text);
    limitsList.append(item);
  }

  async function hash(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function verifyFiles() {
    const button = $("verify-button");
    const rows = $("file-checks");
    button.disabled = true;
    rows.replaceChildren();
    $("integrity-status").textContent = "Checking source files...";
    let allMatch = true;
    for (const [name, expected] of Object.entries(evidence.sourceHashes)) {
      const row = document.createElement("div");
      row.className = "file-row";
      const label = document.createElement("span");
      label.textContent = name;
      const result = document.createElement("span");
      try {
        const response = await fetch(`source/${name}`);
        if (!response.ok) throw new Error("missing");
        const actual = await hash(await response.arrayBuffer());
        const matches = actual === expected;
        allMatch &&= matches;
        result.className = matches ? "ok" : "bad";
        result.textContent = matches ? "SHA256 matches" : "HASH MISMATCH";
      } catch {
        allMatch = false;
        result.className = "bad";
        result.textContent = "FILE UNAVAILABLE";
      }
      row.append(label, result);
      rows.append(row);
    }
    const hashesAgree = artifact.specHash === artifact.certificateSpecHash && artifact.specHash === artifact.reportSpecHash;
    allMatch &&= hashesAgree;
    const finalRow = document.createElement("div");
    finalRow.className = "file-row";
    const finalLabel = document.createElement("span");
    finalLabel.textContent = "spec / certificate / report";
    const finalStatus = document.createElement("span");
    finalStatus.className = hashesAgree ? "ok" : "bad";
    finalStatus.textContent = hashesAgree ? "SPEC HASHES AGREE" : "SPEC HASH MISMATCH";
    finalRow.append(finalLabel, finalStatus);
    rows.append(finalRow);
    $("integrity-status").textContent = allMatch
      ? "All bundled files match the pinned hashes. This does not establish a trusted registry root."
      : "One or more saved artifacts do not match the pinned evidence.";
    button.disabled = false;
  }

  $("verify-button").addEventListener("click", verifyFiles);
  await verifyFiles();
}());
