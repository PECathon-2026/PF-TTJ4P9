const $ = (id) => document.getElementById(id);
const call = (m) => new Promise((r) => chrome.runtime.sendMessage(m, r));
const activeTab = async () =>
  (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
const F = ["provider", "endpoint", "model", "apiKey"];
const B = ["localOnly", "sendScreenshots", "strictMessages"];

document.querySelectorAll("nav button").forEach((b) =>
  b.addEventListener("click", () => {
    document
      .querySelectorAll("nav button")
      .forEach((x) => x.setAttribute("aria-selected", x === b));
    document
      .querySelectorAll(".pane")
      .forEach((p) => p.classList.toggle("on", p.id === "p-" + b.dataset.t));
    if (b.dataset.t === "log") loadLog();
  }),
);

async function load() {
  const s = await chrome.storage.local.get(null);
  F.forEach((k) => {
    if (s[k] != null) $(k).value = s[k];
  });
  B.forEach((k) => {
    $(k).checked = s[k] != null ? s[k] : k !== "sendScreenshots";
  });
  $("selectors").value = ((s.rules && s.rules.selectors) || []).join("\n");
  $("patterns").value = ((s.rules && s.rules.patterns) || [])
    .map((p) => p.type + "=" + p.pattern)
    .join("\n");
  $("vault").value = s.vault ? JSON.stringify(s.vault, null, 1) : "";
  if (!$("provider").value) $("provider").value = "mock";
  if (!$("endpoint").value) $("endpoint").value = "http://localhost:11434";
  if (!$("model").value) $("model").value = "llama3.2";
  showMode();
}
function showMode() {
  const p = $("provider").value;
  $("mode").textContent =
    p === "mock"
      ? "Fully offline"
      : $("localOnly").checked
        ? "Local model only"
        : "Cloud model (sanitised data)";
}
$("provider").addEventListener("change", showMode);
$("localOnly").addEventListener("change", showMode);

$("save").addEventListener("click", async () => {
  let vault = {};
  try {
    vault = $("vault").value.trim() ? JSON.parse($("vault").value) : {};
  } catch (e) {
    return setStatus("Vault is not valid JSON.");
  }
  const rules = {
    selectors: $("selectors")
      .value.split("\n")
      .map((x) => x.trim())
      .filter(Boolean),
    patterns: $("patterns")
      .value.split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const i = l.indexOf("=");
        return { type: l.slice(0, i), pattern: l.slice(i + 1) };
      }),
  };
  const out = { rules, vault };
  F.forEach((k) => {
    out[k] = $(k).value.trim();
  });
  B.forEach((k) => {
    out[k] = $(k).checked;
  });
  await chrome.storage.local.set(out);
  showMode();
  setStatus("Settings saved.");
});

const setStatus = (t) => {
  $("status").textContent = t;
};
chrome.runtime.onMessage.addListener((m) => {
  if (m.type === "PL_STATUS") setStatus(m.text);
});

$("run").addEventListener("click", async () => {
  const task = $("task").value.trim();
  if (!task) return setStatus("Describe a task first.");
  setStatus("Starting…");
  await call({ type: "PL_RUN", tabId: (await activeTab()).id, task });
});
$("stop").addEventListener("click", async () => {
  await call({ type: "PL_STOP", tabId: (await activeTab()).id });
  setStatus("Stopping after the current step.");
});

async function preview(shot) {
  setStatus("Sanitising locally…");
  $("verdict").hidden = true;
  const r = await call({
    type: "PL_PREVIEW",
    tabId: (await activeTab()).id,
    screenshot: shot,
  });
  if (!r || r.error)
    return setStatus(
      (r && r.error) || "No response from the page. Reload the tab once.",
    );
  const b = $("before"),
    a = $("after");
  b.textContent = a.textContent = "";
  r.lines.forEach((l) => {
    const eb = document.createElement("span"),
      ea = document.createElement("span");
    eb.textContent = l.raw + "\n";
    ea.textContent = l.safe + "\n";
    if (l.raw !== l.safe) {
      eb.className = "chg-b";
      ea.className = "chg-a";
    }
    b.appendChild(eb);
    a.appendChild(ea);
  });
  const red = r.stats.redactions || {};
  $("pstats").textContent =
    "Redactions: " +
    (Object.entries(red)
      .map(([k, v]) => `${k} ×${v}`)
      .join(", ") || "none") +
    ` · hidden elements skipped: ${r.stats.hiddenSkipped} · injection phrases removed: ${r.stats.injections}`;
  $("shots").hidden = !(r.shots && r.shots.after);
  if (r.shots && r.shots.after) {
    $("shotB").src = r.shots.before;
    $("shotA").src = r.shots.after;
  }
  setStatus(
    r.shots && r.shots.error
      ? "Preview ready (screenshot failed: " + r.shots.error + ")"
      : "Preview ready.",
  );
}
$("prev").addEventListener("click", () => preview(false));
$("prevShot").addEventListener("click", () => preview(true));

$("unsafe").addEventListener("click", async () => {
  const r = await call({
    type: "PL_UNSAFE_DEMO",
    tabId: (await activeTab()).id,
  });
  const v = $("verdict");
  v.hidden = false;
  v.className = r.blocked ? "blocked" : "";
  v.textContent = "";
  const b = document.createElement("b");
  b.textContent = r.blocked
    ? "Blocked. "
    : "NOT blocked (nothing sensitive found). ";
  v.appendChild(b);
  v.appendChild(
    document.createTextNode(
      r.blocked
        ? `A ${r.bytes}-byte raw payload was stopped before transmission. Violations: ` +
            Object.entries(r.byType)
              .map(([k, n]) => `${k} ×${n}`)
              .join(", ") +
            "."
        : "The raw payload contained no detectable sensitive data.",
    ),
  );
});

async function loadLog() {
  const r = await call({ type: "PL_LOG_GET" });
  $("log").textContent =
    (r.log || [])
      .map((x) => {
        const { t, e, ...rest } = x;
        return `${t.slice(11, 19)}  ${e}  ${Object.keys(rest).length ? JSON.stringify(rest) : ""}`;
      })
      .join("\n") || "No events yet.";
}
$("refreshLog").addEventListener("click", loadLog);
$("clearLog").addEventListener("click", async () => {
  await call({ type: "PL_LOG_CLEAR" });
  loadLog();
});
load();
