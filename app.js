// AuthSentry demo UI. Every value from the log is rendered with textContent, never innerHTML,
// so a malicious log line cannot inject markup into this page.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const logEl = $("log"), formatEl = $("format"), yearEl = $("year"), statusEl = $("status");
  let lastMarkdown = "";

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function setStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.classList.toggle("error", !!isError);
  }

  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      setStatus("Loading sample…");
      try {
        const res = await fetch(btn.dataset.sample, { cache: "no-store" });
        if (!res.ok) throw new Error("HTTP " + res.status);
        logEl.value = await res.text();
        formatEl.value = btn.dataset.format;
        setStatus("Sample loaded. Press Analyze.");
      } catch (e) {
        setStatus("Could not load the sample: " + e.message, true);
      }
    });
  });

  $("file-btn").addEventListener("click", () => $("file").click());
  $("file").addEventListener("change", async (ev) => {
    const f = ev.target.files[0];
    if (!f) return;
    if (f.size > 1000000) return setStatus("File is larger than 1 MB.", true);
    logEl.value = await f.text();
    formatEl.value = "auto";
    setStatus("Loaded " + f.name + ". Press Analyze.");
  });

  $("run").addEventListener("click", analyze);
  logEl.addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") analyze(); });

  async function analyze() {
    const log = logEl.value;
    if (!log.trim()) return setStatus("Paste a log or load a sample first.", true);
    $("run").disabled = true;
    setStatus("Analyzing…");
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log: log, format: formatEl.value, year: Number(yearEl.value) || undefined }),
      });
      const data = await res.json().catch(() => ({ error: "Server returned HTTP " + res.status }));
      if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
      render(data);
      const n = data.alerts.length;
      setStatus(n ? n + (n === 1 ? " alert." : " alerts.") : "No alerts.");
    } catch (e) {
      setStatus(e.message, true);
    } finally {
      $("run").disabled = false;
    }
  }

  function render(data) {
    const s = data.summary;
    const sum = $("summary");
    sum.replaceChildren();
    const stats = [
      ["Auth events", s.events], ["Alerts", s.alerts],
      ["Critical", s.alerts_by_severity.critical], ["High", s.alerts_by_severity.high],
      ["Medium", s.alerts_by_severity.medium], ["Sources", s.unique_sources],
    ];
    stats.forEach(([k, v]) => {
      const box = el("div", "stat" + (["Critical", "High", "Medium"].includes(k) ? " sev-" + k.toLowerCase() : ""));
      box.append(el("span", "stat-v", v), el("span", "stat-k", k));
      sum.append(box);
    });
    (s.warnings || []).forEach((w) => sum.append(el("p", "warn", w)));

    const list = $("alerts");
    list.replaceChildren();
    if (!data.alerts.length) list.append(el("p", "panel muted", "No rule fired on this input. Nothing to escalate."));
    data.alerts.forEach((a) => list.append(alertCard(a)));

    lastMarkdown = data.markdown;
    $("markdown").textContent = data.markdown;
    $("results").hidden = false;
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function alertCard(a) {
    const card = el("article", "alert sev-" + a.severity);
    const head = el("div", "alert-head");
    head.append(el("span", "badge", a.severity.toUpperCase()), el("span", "inc", a.incident_id));
    const h = el("h3", null, a.rule_id + " · " + a.rule_name);
    const attack = el("a", "attack", a.attack.technique + " " + (a.attack.name || ""));
    attack.href = a.attack.url;
    attack.target = "_blank";
    attack.rel = "noopener noreferrer";
    head.append(attack);
    card.append(head, h, el("p", "detail", a.detail));

    const meta = el("dl", "meta");
    [["Source IPs", a.src_ips.join(", ") || "-"], ["Accounts", a.users.join(", ") || "-"],
     ["Hosts", a.hosts.join(", ") || "-"], ["Window", a.first_seen.replace("T", " ").slice(0, 19) + " → " + a.last_seen.replace("T", " ").slice(0, 19) + " (" + a.duration + ")"]]
      .concat(a.workstations.length ? [["Workstations", a.workstations.join(", ")]] : [])
      .forEach(([k, v]) => { meta.append(el("dt", null, k), el("dd", null, v)); });
    card.append(meta);

    const ev = el("details", "evidence");
    ev.append(el("summary", null, "Evidence (" + a.evidence.length + " of " + a.event_count + " events)"));
    const pre = el("pre");
    pre.textContent = a.evidence.map((e) => String(e.line).padStart(5) + ": " + e.raw).join("\n");
    ev.append(pre);
    card.append(ev);

    const tri = el("div", "triage");
    tri.append(el("h4", null, "Triage"));
    const ol = el("ol");
    a.triage.forEach((t) => ol.append(el("li", null, t)));
    tri.append(ol, el("p", "esc", "Escalation: " + a.escalation));
    card.append(tri);
    return card;
  }

  $("download").addEventListener("click", () => {
    if (!lastMarkdown) return;
    const url = URL.createObjectURL(new Blob([lastMarkdown], { type: "text/markdown" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "authsentry-report.md";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
