// The window's whole behaviour: Home is a quick on/off switch over the daemon; Settings holds
// the engine's configuration. No framework — the interesting logic lives in Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const $ = (id) => document.getElementById(id);

const POLL_STATUS_MS = 1500;
const POLL_LOG_MS = 2000;
const LOG_LINES = 250;
const HOME_LOG_LINES = 15;

// The latest state the backend reported, kept here so views can re-render each other.
let config = null;
let ca = null;
let daemon = null;
// "start" | "stop" while a toggle action is in flight; keeps the poll from fighting the user.
let userIntent = null;

// ── feedback ─────────────────────────────────────────────────────────────────

function toast(message, kind = "error") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  el.title = "click to dismiss";
  el.addEventListener("click", () => el.remove());
  $("toasts").append(el);
  setTimeout(() => el.remove(), kind === "error" ? 12000 : 3500);
}

function fail(context, error) {
  const text = typeof error === "string" ? error : error?.message ? error.message : String(error);
  console.error(context, error);
  toast(`${context}\n${text}`);
}

function banner(message) {
  const el = $("banner");
  if (!message) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = message;
  el.classList.remove("hidden");
}

// ── navigation ───────────────────────────────────────────────────────────────

function showView(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("active", tab.dataset.view === name);
  }
  $("view-home").classList.toggle("hidden", name !== "home");
  $("view-settings").classList.toggle("hidden", name !== "settings");
}

// ── config (Settings) ────────────────────────────────────────────────────────

function buildSlotRows(slots) {
  const container = $("slot-rows");
  for (const slot of slots) {
    const row = document.createElement("div");
    row.className = "slot-row";
    const label = document.createElement("div");
    label.className = "slot-label";
    const code = document.createElement("code");
    code.textContent = slot.id;
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = slot.name;
    label.append(code, name);
    const input = document.createElement("input");
    input.type = "text";
    input.spellcheck = false;
    input.placeholder = "(pass through)";
    input.dataset.slot = slot.id;
    row.append(label, input);
    container.append(row);
  }
}

function renderConfig(view) {
  config = view;

  const url = $("base-url");
  if (document.activeElement !== url) url.value = view.base_url ?? "";

  $("api-key-hint").textContent = view.api_key_set
    ? "A key is stored. Leave the field empty to keep it."
    : "No key stored yet.";
  $("api-key").placeholder = view.api_key_set ? "•••••••• (stored)" : "sk-…";

  // The slot grid is static (the protocol's model list); only its values track the config,
  // and never while the user is editing that input.
  if ($("slot-rows").children.length === 0) buildSlotRows(view.slots);
  for (const input of document.querySelectorAll("#slot-rows input")) {
    if (document.activeElement !== input) {
      const entry = view.models.find((m) => m.kiro === input.dataset.slot);
      input.value = entry?.provider ?? "";
    }
  }

  const fallback = $("default-model");
  if (document.activeElement !== fallback) fallback.value = view.default_model ?? "";

  // The footer names the config file, not its absolute path — the path is long and unhelpful here.
  const configFile = view.config_path?.split(/[/\\]/).pop();
  $("config-path").textContent = configFile ? `config: ${configFile}` : "";

  renderChecklist();
  renderDaemon(daemon);
}

async function refreshConfig() {
  try {
    renderConfig(await invoke("get_config"));
    banner(null);
  } catch (error) {
    fail("Reading configuration", error);
  }
}

async function saveProvider() {
  const view = await invoke("set_provider_config", {
    baseUrl: $("base-url").value,
    apiKey: $("api-key").value,
  });
  $("api-key").value = "";
  renderConfig(view);
  toast("Provider saved.", "ok");
}

/** Collect every slot + the custom row into one replace-whole-map call. */
async function applyMappings() {
  const rows = [];
  for (const input of document.querySelectorAll("#slot-rows input")) {
    const provider = input.value.trim();
    if (provider) rows.push({ kiro: input.dataset.slot, provider });
  }
  const customId = $("custom-kiro").value.trim();
  if (customId) rows.push({ kiro: customId, provider: $("custom-provider").value.trim() });

  renderConfig(await invoke("set_model_mappings", { models: rows }));
  $("custom-kiro").value = "";
  $("custom-provider").value = "";
  toast("Mappings saved.", "ok");
}

async function saveFallback(value) {
  renderConfig(await invoke("set_default_model", { providerModel: value }));
}

// ── certificate (Settings) ───────────────────────────────────────────────────

function renderCa(status) {
  ca = status;
  $("ca-fingerprint").textContent = status.fingerprint ?? "not initialized";
  const trusted = $("ca-trusted");
  trusted.textContent = !status.initialized
    ? "not initialized"
    : status.trusted
      ? "trusted"
      : "not trusted";
  trusted.dataset.state = !status.initialized ? "unknown" : status.trusted ? "trusted" : "untrusted";

  const setup = $("ca-setup");
  setup.disabled = Boolean(status.trusted);
  setup.textContent = status.trusted
    ? "Trusted ✓"
    : status.initialized
      ? "Auto setup (install trust)"
      : "Auto setup (mint + trust)";

  renderChecklist();
}

/** The one-click CA setup: mint + trust, one administrator prompt. */
async function autoSetupCa() {
  renderCa(await invoke("install_ca"));
  toast("Root CA minted and trusted.", "ok");
}

async function refreshCa() {
  try {
    renderCa(await invoke("ca_status"));
  } catch (error) {
    fail("Reading certificate status", error);
  }
}

// ── readiness (Home) ─────────────────────────────────────────────────────────

function renderChecklist() {
  const ready = Boolean(config && (config.models.length > 0 || config.default_model));
  const caTrusted = Boolean(ca?.trusted);
  const items = [
    {
      label: "Provider API key",
      ok: Boolean(config?.api_key_set),
      warn: false,
      action: config?.api_key_set
        ? null
        : { label: "set it in Settings", handler: () => showView("settings") },
    },
    {
      label: "Model mapping or fallback",
      ok: ready,
      warn: false,
      action: ready ? null : { label: "add one in Settings", handler: () => showView("settings") },
    },
    {
      label: ca
        ? caTrusted
          ? "Root CA trusted"
          : ca.initialized
            ? "Root CA not trusted"
            : "Root CA not initialized"
        : "Root CA — checking…",
      ok: caTrusted,
      warn: !caTrusted,
      action: ca && !caTrusted ? { label: "auto setup", handler: autoSetupCa } : null,
    },
  ];

  const list = $("checklist");
  list.replaceChildren();
  for (const item of items) {
    const li = document.createElement("li");
    li.className = item.ok ? "ok" : item.warn ? "warn" : "missing";
    const mark = document.createElement("span");
    mark.className = "mark";
    mark.textContent = item.ok ? "✓" : "!";
    const label = document.createElement("span");
    label.textContent = item.label;
    li.append(mark, label);
    if (item.action) {
      const link = document.createElement("a");
      link.className = "checklist-action";
      link.textContent = item.action.label;
      link.addEventListener("click", (e) => run(e.currentTarget, item.action.handler));
      li.append(link);
    }
    list.append(li);
  }
}

// ── proxy (Home) ─────────────────────────────────────────────────────────────

const HERO_TEXT = {
  stopped: "Proxy is off",
  starting: "Starting…",
  running: "Proxy is running",
  failed: "Start failed",
};

function toggleReady() {
  return Boolean(config?.api_key_set && (config.models.length > 0 || config.default_model));
}

function renderDaemon(status) {
  const previous = daemon?.state;
  daemon = status;
  // Trust is installed during daemon startup — re-read it once the proxy is up.
  if (previous !== status.state && status.state === "running") refreshCa();
  // A start that just failed has fresh lines waiting in the daemon log; pull them in now so
  // the panel explains the toast instead of trailing it by a poll interval.
  if (previous !== status.state && status.state === "failed") refreshLog();

  $("proxy-pill").textContent = status.state;
  $("proxy-pill").dataset.state = status.state;

  const hero = $("hero-state");
  hero.textContent = HERO_TEXT[status.state] ?? status.state;
  hero.dataset.state = status.state;

  $("daemon-pid").textContent = status.pid ?? "—";
  $("daemon-port").textContent = status.control_port ?? "—";
  $("daemon-detail").textContent =
    status.detail ?? "Starts 9rai daemon with administrator rights; stopping restores your hosts file.";

  // The switch reflects the daemon unless the user just flipped it themselves.
  const checkbox = $("proxy-toggle");
  checkbox.disabled = !toggleReady();
  if (userIntent) {
    const done =
      (userIntent === "start" && status.state !== "stopped") ||
      (userIntent === "stop" && status.state === "stopped");
    if (done) userIntent = null;
  } else {
    checkbox.checked = status.state !== "stopped" && status.state !== "failed";
  }
  if (!toggleReady()) checkbox.checked = false;
}

async function refreshDaemon() {
  try {
    renderDaemon(await invoke("daemon_status"));
  } catch (error) {
    fail("Reading proxy status", error);
  }
}

async function toggleProxy(on) {
  const checkbox = $("proxy-toggle");
  userIntent = on ? "start" : "stop";
  try {
    renderDaemon(await invoke(on ? "start_proxy" : "stop_proxy"));
  } catch (error) {
    userIntent = null;
    checkbox.checked = !on;
    fail(on ? "Starting the proxy" : "Stopping the proxy", error);
    // The backend writes the reason into the daemon log; show it without waiting for the poll.
    refreshLog();
  }
}

// ── log ──────────────────────────────────────────────────────────────────────

async function refreshLog() {
  try {
    const lines = await invoke("daemon_log", { lines: LOG_LINES });
    $("daemon-log").textContent = lines.length ? lines.join("\n") : "(no output yet)";
    $("home-log").textContent = lines.length
      ? lines.slice(-HOME_LOG_LINES).join("\n")
      : "(no output yet)";
  } catch (error) {
    console.error("Reading daemon log", error);
  }
}

// ── plumbing ─────────────────────────────────────────────────────────────────

/** Disable an element for the duration of an async action, surfacing failures as a toast. */
async function run(button, action) {
  if (button) {
    button.disabled = true;
    button.classList.add("busy");
  }
  try {
    await action();
  } catch (error) {
    fail(button?.textContent ? `“${button.textContent.trim()}” failed` : "Action failed", error);
  } finally {
    if (button) {
      button.disabled = false;
      button.classList.remove("busy");
    }
  }
}

function bind() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => showView(tab.dataset.view));
  }

  $("proxy-toggle").addEventListener("change", (e) => toggleProxy(e.currentTarget.checked));

  $("save-provider").addEventListener("click", (e) => run(e.currentTarget, saveProvider));
  $("apply-mappings").addEventListener("click", (e) => run(e.currentTarget, applyMappings));
  $("save-default").addEventListener("click", (e) =>
    run(e.currentTarget, () => saveFallback($("default-model").value)),
  );
  $("clear-default").addEventListener("click", (e) =>
    run(e.currentTarget, () => saveFallback(null)),
  );
  $("ca-setup").addEventListener("click", (e) => run(e.currentTarget, autoSetupCa));

  // Enter submits the row it belongs to.
  $("api-key").addEventListener("keydown", (e) => e.key === "Enter" && $("save-provider").click());
  $("custom-provider").addEventListener("keydown", (e) => e.key === "Enter" && $("apply-mappings").click());
}

async function boot() {
  bind();
  showView("home");
  await Promise.all([refreshConfig(), refreshCa(), refreshDaemon(), refreshLog()]);

  try {
    await listen("proxy-status-changed", (event) => renderDaemon(event.payload));
  } catch (error) {
    console.warn("event bridge unavailable", error);
  }

  setInterval(refreshDaemon, POLL_STATUS_MS);
  setInterval(refreshLog, POLL_LOG_MS);
}

boot();
