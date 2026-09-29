// The window's whole behaviour: 4-tab architecture
// Dashboard: 2-in-1 control hub for Proxy & Accounts
// AI Router: Provider endpoint & Model mapping studio
// Accounts: Kiro account pool & switcher
// Diagnostics: Root CA, Hosts file, and live daemon logs

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { confirm, open } from "@tauri-apps/plugin-dialog";

const $ = (id) => document.getElementById(id);

const POLL_STATUS_MS = 1500;
const POLL_LOG_MS = 2000;
const LOG_LINES = 250;

// State kept in window memory
// State kept in window memory
let config = null;
let ca = null;
let daemon = null;
let accounts = null;
let importPath = null;
let userIntent = null;
let pendingElevationAction = null;
let isStrandedHosts = false;
let customMappings = [];
let isDirty = false;
let currentFamilyFilter = "all";
let currentAcctFilter = "all";
let currentAcctSearch = "";
let currentAcctSort = "default";

// Presets for popular providers
const PRESETS = {
  "9router": {
    name: "9Router (Local)",
    baseUrl: "http://127.0.0.1:20128/v1",
    slots: {
      auto: "deepseek-v4-pro",
      "simple-task": "deepseek-v4-pro",
      "claude-sonnet-4": "claude-sonnet-4",
      "claude-sonnet-4.5": "claude-sonnet-4.5",
      "claude-sonnet-5": "claude-sonnet-5",
      "claude-haiku-4.5": "claude-haiku-4.5",
      "deepseek-3.2": "deepseek-v4-pro",
      "minimax-m2.1": "minimax-m2.5",
    },
    defaultModel: "deepseek-v4-pro",
  },
  deepseek: {
    name: "DeepSeek Official",
    baseUrl: "https://api.deepseek.com/v1",
    slots: {
      auto: "deepseek-chat",
      "simple-task": "deepseek-chat",
      "claude-sonnet-4": "deepseek-reasoner",
      "claude-sonnet-4.5": "deepseek-reasoner",
      "deepseek-3.2": "deepseek-chat",
    },
    defaultModel: "deepseek-chat",
  },
  openrouter: {
    name: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    slots: {
      auto: "anthropic/claude-3.5-sonnet",
      "simple-task": "deepseek/deepseek-chat",
      "claude-sonnet-4": "anthropic/claude-3.5-sonnet",
      "claude-sonnet-4.5": "anthropic/claude-3.5-sonnet",
      "claude-haiku-4.5": "anthropic/claude-3.5-haiku",
      "deepseek-3.2": "deepseek/deepseek-chat",
    },
    defaultModel: "anthropic/claude-3.5-sonnet",
  },
  openai: {
    name: "OpenAI Official",
    baseUrl: "https://api.openai.com/v1",
    slots: {
      auto: "gpt-4o",
      "simple-task": "gpt-4o-mini",
      "claude-sonnet-4": "gpt-4o",
      "claude-sonnet-4.5": "gpt-4o",
      "gpt-5.6-sol": "gpt-4o",
      "gpt-5.6-terra": "gpt-4o-mini",
      "gpt-5.6-luna": "o1-mini",
    },
    defaultModel: "gpt-4o",
  },
  ollama: {
    name: "Ollama (Local)",
    baseUrl: "http://localhost:11434/v1",
    slots: {
      auto: "qwen2.5-coder:latest",
      "simple-task": "qwen2.5-coder:latest",
    },
    defaultModel: "qwen2.5-coder:latest",
  },
};

const FAMILIES = {
  claude: {
    id: "claude",
    name: "Dòng Anthropic Claude",
    slots: [
      "claude-sonnet-4.5",
      "claude-sonnet-4",
      "claude-haiku-4.5",
      "claude-sonnet-5",
      "claude-sonnet-4.6",
      "claude-opus-5",
      "claude-opus-4.8",
    ],
  },
  deepseek: {
    id: "deepseek",
    name: "Dòng DeepSeek & MiniMax",
    slots: ["deepseek-3.2", "minimax-m2.1"],
  },
  gpt: {
    id: "gpt",
    name: "Dòng OpenAI GPT Series",
    slots: ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"],
  },
};

const KNOWN_SLOT_IDS = new Set([
  "auto",
  "simple-task",
  ...FAMILIES.claude.slots,
  ...FAMILIES.deepseek.slots,
  ...FAMILIES.gpt.slots,
]);

// ── feedback ─────────────────────────────────────────────────────────────────

function toast(message, kind = "error") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  el.title = "nhấn để đóng";
  el.addEventListener("click", () => el.remove());
  $("toasts").append(el);
  setTimeout(() => el.remove(), kind === "error" ? 10000 : 3500);
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
  const target = name === "router" ? "settings" : name;
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("active", tab.dataset.view === target || (tab.dataset.view === "settings" && name === "router"));
  }
  $("view-dashboard").classList.toggle("hidden", target !== "dashboard");
  const settingsEl = $("view-settings") || $("view-router");
  if (settingsEl) settingsEl.classList.toggle("hidden", target !== "settings");
  $("view-accounts").classList.toggle("hidden", target !== "accounts");
  $("view-diagnostics").classList.toggle("hidden", target !== "diagnostics");
}

// ── settings / router ────────────────────────────────────────────────────────

function setDirty(dirty) {
  isDirty = dirty;
  const dot = $("dirty-dot");
  const text = $("dirty-text");
  if (dot) dot.classList.toggle("dirty", dirty);
  if (text) {
    text.textContent = dirty
      ? "● Có thay đổi chưa lưu (nhấn Lưu để áp dụng)"
      : "Tất cả cấu hình đã đồng bộ";
  }
}

function updatePipelineSummary() {
  const autoVal = $("slot-auto")?.value.trim() || "";
  const simpleVal = $("slot-simple")?.value.trim() || "";
  const defaultVal = $("default-model")?.value.trim() || "";

  if ($("sum-slot-auto")) $("sum-slot-auto").textContent = autoVal || "(chưa đặt)";
  if ($("sum-slot-simple")) $("sum-slot-simple").textContent = simpleVal || "(chưa đặt)";
  if ($("sum-fallback")) $("sum-fallback").textContent = defaultVal || "(Passthrough AWS)";

  if ($("diag-mapped-sample")) {
    $("diag-mapped-sample").textContent = autoVal ? `vd: auto ➔ ${autoVal}` : "Định tuyến sang mô hình tương ứng";
  }
  if ($("diag-fallback-sample")) {
    $("diag-fallback-sample").textContent = defaultVal ? `Dự phòng: ${defaultVal}` : "Nếu trống ➔ Passthrough sang AWS gốc";
  }

  let mappedCount = 0;
  for (const input of document.querySelectorAll("#model-families-container input[data-slot]")) {
    if (input.value.trim()) mappedCount++;
  }
  for (const m of customMappings) {
    if (m.provider.trim()) mappedCount++;
  }
  if ($("sum-mapped-count")) {
    $("sum-mapped-count").textContent = `${mappedCount} model`;
  }
}

function updateTotalModelCount() {
  const total = FAMILIES.claude.slots.length + FAMILIES.deepseek.slots.length + FAMILIES.gpt.slots.length + customMappings.length;
  if ($("count-all")) $("count-all").textContent = String(total);
}

function buildFamilyRows(view) {
  const slotsMap = new Map((view.slots || []).map((s) => [s.id, s]));

  for (const [famKey, fam] of Object.entries(FAMILIES)) {
    const container = $(`rows-${famKey}`);
    if (!container) continue;
    container.replaceChildren();

    for (const slotId of fam.slots) {
      const slot = slotsMap.get(slotId) || { id: slotId, name: slotId };
      const row = document.createElement("div");
      row.className = "model-row-item";
      row.dataset.slot = slot.id;
      row.dataset.name = slot.name;

      const meta = document.createElement("div");
      meta.className = "model-meta";
      const code = document.createElement("code");
      code.textContent = slot.id;
      const desc = document.createElement("span");
      desc.className = "model-desc";
      desc.textContent = slot.name;
      meta.append(code, desc);

      const status = document.createElement("div");
      status.className = "model-status-indicator";
      const dot = document.createElement("span");
      dot.className = "status-dot passthrough";
      const statusTxt = document.createElement("span");
      statusTxt.className = "status-text passthrough";
      statusTxt.textContent = "Passthrough AWS";
      status.append(dot, statusTxt);

      const inputWrap = document.createElement("div");
      inputWrap.className = "model-input-wrap";
      const input = document.createElement("input");
      input.type = "text";
      input.spellcheck = false;
      input.placeholder = "(chuyển tiếp AWS gốc)";
      input.dataset.slot = slot.id;

      function updateStatus() {
        const hasVal = Boolean(input.value.trim());
        dot.className = `status-dot ${hasVal ? "active" : "passthrough"}`;
        statusTxt.className = `status-text ${hasVal ? "active" : "passthrough"}`;
        statusTxt.textContent = hasVal ? "Đã ánh xạ" : "Passthrough AWS";
      }

      input.addEventListener("input", () => {
        updateStatus();
        updatePipelineSummary();
        setDirty(true);
      });

      inputWrap.append(input);
      row.append(meta, status, inputWrap);
      container.append(row);
    }
  }

  if ($("count-claude")) $("count-claude").textContent = String(FAMILIES.claude.slots.length);
  if ($("count-deepseek")) $("count-deepseek").textContent = String(FAMILIES.deepseek.slots.length);
  if ($("count-gpt")) $("count-gpt").textContent = String(FAMILIES.gpt.slots.length);
  updateTotalModelCount();
}

function renderCustomMappings() {
  const container = $("custom-mappings-list");
  if (!container) return;
  container.replaceChildren();

  if (customMappings.length === 0) {
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = "Chưa có ánh xạ tùy chỉnh nào. Thêm ánh xạ mới ở bên dưới:";
    container.append(hint);
  } else {
    customMappings.forEach((item, idx) => {
      const row = document.createElement("div");
      row.className = "custom-row-item";

      const code = document.createElement("span");
      code.className = "custom-kiro-code";
      code.textContent = item.kiro;

      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.textContent = "➔";

      const input = document.createElement("input");
      input.type = "text";
      input.value = item.provider;
      input.spellcheck = false;
      input.placeholder = "Model nhà cung cấp";
      input.addEventListener("input", (e) => {
        item.provider = e.target.value.trim();
        updatePipelineSummary();
        setDirty(true);
      });

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "custom-del-btn";
      delBtn.textContent = "🗑️";
      delBtn.title = "Xóa ánh xạ này";
      delBtn.addEventListener("click", () => {
        customMappings.splice(idx, 1);
        renderCustomMappings();
        updatePipelineSummary();
        setDirty(true);
      });

      row.append(code, arrow, input, delBtn);
      container.append(row);
    });
  }

  if ($("count-custom")) $("count-custom").textContent = String(customMappings.length);
  if ($("badge-count-custom")) $("badge-count-custom").textContent = `${customMappings.length} models`;
  updateTotalModelCount();
}

function addCustomMapping() {
  const kiroInput = $("custom-kiro");
  const provInput = $("custom-provider");
  const kiro = kiroInput.value.trim();
  const provider = provInput.value.trim();

  if (!kiro) {
    toast("Vui lòng nhập mã Kiro model tùy chỉnh");
    kiroInput.focus();
    return;
  }
  if (!provider) {
    toast("Vui lòng nhập tên model nhà cung cấp đích");
    provInput.focus();
    return;
  }

  const existing = customMappings.find((m) => m.kiro === kiro);
  if (existing) {
    existing.provider = provider;
  } else {
    customMappings.push({ kiro, provider });
  }

  kiroInput.value = "";
  provInput.value = "";
  renderCustomMappings();
  updatePipelineSummary();
  setDirty(true);
  toast(`Đã thêm ánh xạ '${kiro}' ➔ '${provider}'`, "ok");
}

function filterModels(query, familyFilter) {
  const q = (query || "").trim().toLowerCase();
  currentFamilyFilter = familyFilter || currentFamilyFilter || "all";

  for (const group of document.querySelectorAll(".family-group")) {
    const fam = group.dataset.family;
    const matchFamily = currentFamilyFilter === "all" || currentFamilyFilter === fam;
    if (!matchFamily) {
      group.classList.add("hidden");
      continue;
    }
    group.classList.remove("hidden");

    if (fam === "custom") {
      for (const row of group.querySelectorAll(".custom-row-item")) {
        const text = row.textContent.toLowerCase();
        const val = row.querySelector("input")?.value.toLowerCase() || "";
        const matches = !q || text.includes(q) || val.includes(q);
        row.classList.toggle("hidden", !matches);
      }
    } else {
      for (const row of group.querySelectorAll(".model-row-item")) {
        const slotId = (row.dataset.slot || "").toLowerCase();
        const name = (row.dataset.name || "").toLowerCase();
        const val = (row.querySelector("input")?.value || "").toLowerCase();
        const matches = !q || slotId.includes(q) || name.includes(q) || val.includes(q);
        row.classList.toggle("hidden", !matches);
      }
    }
  }
}

function applyPreset(key) {
  const preset = PRESETS[key];
  if (!preset) return;

  $("base-url").value = preset.baseUrl;
  $("slot-auto").value = preset.slots["auto"] ?? "";
  $("slot-simple").value = preset.slots["simple-task"] ?? "";
  $("default-model").value = preset.defaultModel || "";

  for (const input of document.querySelectorAll("#model-families-container input[data-slot]")) {
    const slotId = input.dataset.slot;
    input.value = preset.slots[slotId] ?? "";
    const row = input.closest(".model-row-item");
    if (row) {
      const hasVal = Boolean(input.value.trim());
      const dot = row.querySelector(".status-dot");
      const statusTxt = row.querySelector(".status-text");
      if (dot) dot.className = `status-dot ${hasVal ? "active" : "passthrough"}`;
      if (statusTxt) {
        statusTxt.className = `status-text ${hasVal ? "active" : "passthrough"}`;
        statusTxt.textContent = hasVal ? "Đã ánh xạ" : "Passthrough AWS";
      }
    }
  }

  for (const card of document.querySelectorAll(".preset-card")) {
    card.classList.toggle("active", card.dataset.preset === key);
  }

  updatePipelineSummary();
  setDirty(true);
  toast(`Đã áp dụng mẫu ${preset.name}. Nhập API key và nhấn Lưu tất cả.`, "ok");
}

function toggleKeyVisibility() {
  const input = $("api-key");
  const isPass = input.type === "password";
  input.type = isPass ? "text" : "password";
  $("toggle-key-visibility").textContent = isPass ? "🔒" : "👁️";
}

function formatProviderDisplay(baseUrl) {
  if (!baseUrl) return "Chưa cấu hình";
  try {
    const u = new URL(baseUrl);
    if (u.hostname.includes("deepseek.com")) return "DeepSeek API";
    if (u.hostname.includes("openrouter.ai")) return "OpenRouter";
    if (u.hostname.includes("openai.com")) return "OpenAI";
    if (u.hostname === "127.0.0.1" && u.port === "20128") return "9Router Local";
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return `Local LLM (${u.port})`;
    return u.hostname;
  } catch {
    return baseUrl;
  }
}

async function testProviderConnection() {
  const baseUrl = $("base-url").value.trim();
  const apiKey = $("api-key").value.trim() || null;
  const resBox = $("connection-test-result");
  const btn = $("btn-test-connection");

  if (!baseUrl) {
    toast("Vui lòng nhập Base URL trước khi kiểm tra kết nối");
    $("base-url").focus();
    return;
  }

  btn.disabled = true;
  btn.classList.add("busy");
  resBox.className = "test-result-box hidden";
  resBox.textContent = "";

  try {
    const res = await invoke("test_provider_connection", { baseUrl, apiKey });
    resBox.classList.remove("hidden");
    if (res.ok) {
      resBox.className = "test-result-box success";
      let html = `
        <div class="test-res-head">
          <strong>${res.message}</strong>
          <span class="latency-badge">${res.latency_ms}ms</span>
        </div>
      `;
      if (res.models && res.models.length > 0) {
        html += `<span class="res-models-label">Mô hình khả dụng từ nhà cung cấp (${res.models.length}) — nhấn để điền vào ô đang chọn:</span>`;
        html += `<div class="res-models-chips">`;
        for (const m of res.models) {
          html += `<button type="button" class="model-chip-clickable" data-model="${m}">${m}</button>`;
        }
        html += `</div>`;
      }
      resBox.innerHTML = html;

      for (const chip of resBox.querySelectorAll(".model-chip-clickable")) {
        chip.addEventListener("click", () => {
          const modelName = chip.dataset.model;
          const active = document.activeElement;
          if (active && active.tagName === "INPUT" && active.type === "text") {
            active.value = modelName;
            active.dispatchEvent(new Event("input"));
            toast(`Đã điền '${modelName}' vào ô đang chọn`, "ok");
          } else {
            $("slot-auto").value = modelName;
            $("slot-auto").dispatchEvent(new Event("input"));
            toast(`Đã điền '${modelName}' vào Agent chính (auto)`, "ok");
          }
        });
      }
    } else {
      resBox.className = "test-result-box error";
      resBox.innerHTML = `
        <div class="test-res-head">
          <strong>${res.message}</strong>
          <span class="latency-badge">${res.latency_ms > 0 ? res.latency_ms + "ms" : "Lỗi"}</span>
        </div>
        <p class="hint">Hãy kiểm tra lại Base URL (chuẩn OpenAI), tính chính xác của API Key hoặc mạng máy tính.</p>
      `;
    }
  } catch (err) {
    resBox.classList.remove("hidden");
    resBox.className = "test-result-box error";
    resBox.textContent = `Lỗi kiểm tra kết nối: ${err}`;
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
  }
}

function renderConfig(view) {
  config = view;

  const url = $("base-url");
  if (document.activeElement !== url) url.value = view.base_url ?? "";

  $("api-key-hint").textContent = view.api_key_set
    ? "Đã lưu API key (bảo mật 0600). Để trống ô nếu muốn giữ nguyên key hiện tại."
    : "Chưa có API key nào được lưu.";
  $("api-key").placeholder = view.api_key_set ? "•••••••• (đã lưu)" : "sk-…";

  // Primary model slots
  const autoEntry = view.models.find((m) => m.kiro === "auto");
  if (document.activeElement !== $("slot-auto")) {
    $("slot-auto").value = autoEntry?.provider ?? "";
  }

  const simpleEntry = view.models.find((m) => m.kiro === "simple-task");
  if (document.activeElement !== $("slot-simple")) {
    $("slot-simple").value = simpleEntry?.provider ?? "";
  }

  const fallback = $("default-model");
  if (document.activeElement !== fallback) {
    fallback.value = view.default_model ?? "";
  }

  // Build model families rows if empty
  if ($("rows-claude")?.children.length === 0) {
    buildFamilyRows(view);
  }

  // Populate specific slot inputs
  for (const input of document.querySelectorAll("#model-families-container input[data-slot]")) {
    if (document.activeElement !== input) {
      const entry = view.models.find((m) => m.kiro === input.dataset.slot);
      input.value = entry?.provider ?? "";
      const row = input.closest(".model-row-item");
      if (row) {
        const hasVal = Boolean(input.value.trim());
        const dot = row.querySelector(".status-dot");
        const statusTxt = row.querySelector(".status-text");
        if (dot) dot.className = `status-dot ${hasVal ? "active" : "passthrough"}`;
        if (statusTxt) {
          statusTxt.className = `status-text ${hasVal ? "active" : "passthrough"}`;
          statusTxt.textContent = hasVal ? "Đã ánh xạ" : "Passthrough AWS";
        }
      }
    }
  }

  // Extract custom mappings (models not in known slots)
  customMappings = view.models.filter((m) => !KNOWN_SLOT_IDS.has(m.kiro));
  renderCustomMappings();
  updatePipelineSummary();

  // Highlight matching preset if any
  for (const card of document.querySelectorAll(".preset-card")) {
    const p = PRESETS[card.dataset.preset];
    card.classList.toggle("active", Boolean(p && p.baseUrl === view.base_url));
  }

  // Update Dashboard Card 1 metadata
  $("dash-provider-name").textContent = formatProviderDisplay(view.base_url);
  $("dash-primary-model").textContent = autoEntry?.provider || view.default_model || "(chưa đặt)";
  $("dash-fallback-model").textContent = view.default_model || "(chuyển tiếp AWS gốc)";

  // System settings in Settings view
  if ($("set-config-path")) $("set-config-path").textContent = view.config_path || "config.json";

  // Footer config file name
  const configFile = view.config_path?.split(/[/\\]/).pop();
  $("config-path").textContent = configFile ? `config: ${configFile}` : "";

  setDirty(false);
  renderOnboarding();
  renderHealthBar();
}

async function refreshConfig() {
  try {
    renderConfig(await invoke("get_config"));
    banner(null);
  } catch (error) {
    fail("Đọc cấu hình thất bại", error);
  }
}

async function saveAllSettings() {
  const baseUrl = $("base-url").value.trim();
  const apiKey = $("api-key").value.trim() || null;
  const rows = [];

  const autoVal = $("slot-auto").value.trim();
  if (autoVal) rows.push({ kiro: "auto", provider: autoVal });

  const simpleVal = $("slot-simple").value.trim();
  if (simpleVal) rows.push({ kiro: "simple-task", provider: simpleVal });

  for (const input of document.querySelectorAll("#model-families-container input[data-slot]")) {
    const provider = input.value.trim();
    if (provider) rows.push({ kiro: input.dataset.slot, provider });
  }

  for (const item of customMappings) {
    const prov = item.provider.trim();
    if (prov && item.kiro.trim()) {
      rows.push({ kiro: item.kiro.trim(), provider: prov });
    }
  }

  const customId = $("custom-kiro")?.value.trim();
  const customProv = $("custom-provider")?.value.trim();
  if (customId && customProv) {
    rows.push({ kiro: customId, provider: customProv });
  }

  const defaultModel = $("default-model").value.trim() || null;

  try {
    const view = await invoke("save_all_settings", {
      baseUrl,
      apiKey,
      models: rows,
      defaultModel,
    });
    $("api-key").value = "";
    if ($("custom-kiro")) $("custom-kiro").value = "";
    if ($("custom-provider")) $("custom-provider").value = "";
    renderConfig(view);
    setDirty(false);
    toast("Đã lưu tất cả cấu hình thành công! ✓", "ok");
  } catch (error) {
    fail("Lưu cài đặt", error);
  }
}

function resetSettings() {
  if (config) {
    renderConfig(config);
    setDirty(false);
    toast("Đã hoàn tác về cấu hình đã lưu.", "ok");
  }
}

// ── certificate (Diagnostics) ────────────────────────────────────────────────

function renderCa(status) {
  ca = status;
  $("ca-fingerprint").textContent = status.fingerprint ?? "chưa khởi tạo";
  const trusted = $("ca-trusted");
  trusted.textContent = !status.initialized
    ? "chưa khởi tạo"
    : status.trusted
      ? "đã tin cậy (trusted)"
      : "chưa tin cậy (not trusted)";
  trusted.dataset.state = !status.initialized ? "unknown" : status.trusted ? "trusted" : "untrusted";

  const setup = $("ca-setup");
  setup.disabled = Boolean(status.trusted);
  setup.textContent = status.trusted
    ? "Đã tin cậy ✓"
    : status.initialized
      ? "Tự động cài đặt (Cấp tin cậy)"
      : "Tự động cài đặt (Tạo + Tin cậy)";

  // Also sync Settings view system card
  const setTrusted = $("set-ca-trusted");
  if (setTrusted) {
    setTrusted.textContent = !status.initialized
      ? "chưa khởi tạo"
      : status.trusted
        ? "đã tin cậy (trusted)"
        : "chưa tin cậy (untrusted)";
    setTrusted.dataset.state = !status.initialized ? "unknown" : status.trusted ? "trusted" : "untrusted";
  }
  const setFp = $("set-ca-fingerprint");
  if (setFp) setFp.textContent = status.fingerprint ?? "chưa khởi tạo";
  const setSetup = $("set-ca-setup");
  if (setSetup) {
    setSetup.disabled = Boolean(status.trusted);
    setSetup.textContent = status.trusted ? "Đã tin cậy ✓" : "Tự động cài đặt CA 1-Click";
  }

  renderOnboarding();
  renderHealthBar();
}

async function autoSetupCa() {
  try {
    renderCa(await invoke("install_ca"));
    toast("Root CA đã được tạo và cấp tin cậy thành công! ✓", "ok");
  } catch (error) {
    fail("Cài đặt chứng chỉ Root CA", error);
  }
}

async function refreshCa() {
  try {
    renderCa(await invoke("ca_status"));
  } catch (error) {
    fail("Kiểm tra chứng chỉ Root CA", error);
  }
}

// ── onboarding (Dashboard) ───────────────────────────────────────────────────

function renderOnboarding() {
  const guide = $("onboarding-guide");
  if (!guide) return;

  const keyReady = Boolean(config?.api_key_set);
  const modelsReady = Boolean(config && (config.models.length > 0 || config.default_model));
  const providerDone = keyReady && modelsReady;
  const caDone = Boolean(ca?.trusted);
  const proxyRunning = daemon?.state === "running";

  const step1 = $("step-provider");
  if (step1) {
    step1.classList.toggle("done", providerDone);
    const desc = $("step-provider-desc");
    if (desc) desc.textContent = providerDone ? "Đã cấu hình nhà cung cấp và model ✓" : "Chọn preset và nhập API key.";
  }

  const step2 = $("step-ca");
  if (step2) {
    step2.classList.toggle("done", caDone);
    const desc = $("step-ca-desc");
    if (desc) desc.textContent = caDone ? "Chứng chỉ bảo mật đã được tin cậy ✓" : "Cần thiết để Kiro IDE tin cậy kết nối HTTPS.";
  }

  const step3 = $("step-proxy");
  if (step3) {
    step3.classList.toggle("done", proxyRunning);
    const status = $("step-proxy-status");
    if (status) {
      status.textContent = proxyRunning ? "Đang chạy ✓" : providerDone && caDone ? "Sẵn sàng bật" : "Chờ thiết lập";
    }
  }

  if (providerDone && caDone && proxyRunning) {
    guide.classList.add("hidden");
  } else {
    guide.classList.remove("hidden");
  }
}

// ── daemon / proxy ───────────────────────────────────────────────────────────

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
  if (!status) return;
  const previous = daemon?.state;
  daemon = status;
  if (previous !== status.state && status.state === "running") refreshCa();
  if (previous !== status.state && status.state === "failed") refreshLog();

  $("proxy-pill").textContent = status.state;
  $("proxy-pill").dataset.state = status.state;

  $("dash-proxy-badge").textContent = status.state;
  $("dash-proxy-badge").dataset.state = status.state;

  const hero = $("hero-state");
  hero.textContent = HERO_TEXT[status.state] ?? status.state;
  hero.dataset.state = status.state;

  $("daemon-pid").textContent = status.pid ?? "—";
  $("daemon-port").textContent = status.control_port ?? "—";
  $("daemon-detail").textContent =
    status.detail ?? "Khởi chạy 9rai daemon với quyền quản trị viên; khi tắt sẽ tự khôi phục file hosts.";

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

  renderOnboarding();
  renderHealthBar();
  checkStrandedHosts();
}

async function refreshDaemon() {
  try {
    renderDaemon(await invoke("daemon_status"));
  } catch (error) {
    fail("Đọc trạng thái proxy", error);
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
    fail(on ? "Bật proxy thất bại" : "Tắt proxy thất bại", error);
    refreshLog();
  }
}

// ── elevation dialog ─────────────────────────────────────────────────────────

function requestElevation(action, desc) {
  pendingElevationAction = action;
  if (desc) $("elevation-desc").innerHTML = desc;
  $("elevation-modal").classList.remove("hidden");
}

function closeElevationModal() {
  $("elevation-modal").classList.add("hidden");
  pendingElevationAction = null;
}

function promptAutoSetupCa() {
  requestElevation(
    () => autoSetupCa(),
    "9rai sẽ tạo chứng chỉ Root CA cục bộ và thêm vào danh sách tin cậy của máy tính. Thao tác này cần cấp quyền 1 lần duy nhất."
  );
}

function handleToggleProxyChange(e) {
  const wantOn = e.currentTarget.checked;
  if (wantOn) {
    requestElevation(
      () => toggleProxy(true),
      "9rai cần quyền Administrator để lắng nghe cổng mạng <strong>:443</strong> và tạm thời trỏ tên miền Kiro về máy tính cục bộ."
    );
  } else {
    toggleProxy(false);
  }
}

// ── hosts recovery & health ──────────────────────────────────────────────────

async function checkStrandedHosts() {
  if (daemon?.state !== "stopped") {
    isStrandedHosts = false;
    $("stranded-banner").classList.add("hidden");
    $("diag-hosts-status").textContent = "Đang định tuyến (Proxy chạy)";
    if ($("set-hosts-status")) {
      $("set-hosts-status").textContent = "Đang định tuyến (Proxy chạy)";
      $("set-hosts-status").style.color = "var(--ok)";
    }
    renderHealthBar();
    return;
  }
  try {
    isStrandedHosts = await invoke("check_hosts_stranded");
    $("stranded-banner").classList.toggle("hidden", !isStrandedHosts);
    const hostsTxt = isStrandedHosts ? "Chưa dọn dẹp (Lỗi tắt đột ngột)" : "Bình thường (Sạch sẽ)";
    $("diag-hosts-status").textContent = hostsTxt;
    $("diag-hosts-status").style.color = isStrandedHosts ? "var(--bad)" : "var(--ink)";
    if ($("set-hosts-status")) {
      $("set-hosts-status").textContent = hostsTxt;
      $("set-hosts-status").style.color = isStrandedHosts ? "var(--bad)" : "var(--ink)";
    }
    renderHealthBar();
  } catch (error) {
    console.error("Checking hosts stranded status", error);
  }
}

async function restoreHosts() {
  try {
    await invoke("restore_hosts");
    isStrandedHosts = false;
    $("stranded-banner").classList.add("hidden");
    $("diag-hosts-status").textContent = "Bình thường (Sạch sẽ)";
    $("diag-hosts-status").style.color = "var(--ink)";
    if ($("set-hosts-status")) {
      $("set-hosts-status").textContent = "Bình thường (Sạch sẽ)";
      $("set-hosts-status").style.color = "var(--ink)";
    }
    renderHealthBar();
    toast("Đã khôi phục file hosts và mạng Kiro thành công! ✓", "ok");
  } catch (error) {
    fail("Khôi phục file hosts", error);
  }
}

function renderHealthBar() {
  const caTrusted = Boolean(ca?.trusted);
  const caDot = $("health-ca-dot");
  const caText = $("health-ca-text");
  if (caDot && caText) {
    caDot.className = `health-dot ${caTrusted ? "ok" : "warn"}`;
    caText.textContent = caTrusted ? "Đã tin cậy ✓" : "Chưa cài đặt ⚠️";
  }

  const isRunning = daemon?.state === "running";
  const hostsDot = $("health-hosts-dot");
  const hostsText = $("health-hosts-text");
  if (hostsDot && hostsText) {
    if (isStrandedHosts) {
      hostsDot.className = "health-dot bad";
      hostsText.textContent = "Chưa dọn dẹp ⚠️";
    } else if (isRunning) {
      hostsDot.className = "health-dot ok";
      hostsText.textContent = "Đang định tuyến (Loopback)";
    } else {
      hostsDot.className = "health-dot ok";
      hostsText.textContent = "Sạch sẽ ✓";
    }
  }

  const fixBtn = $("health-fix-btn");
  if (fixBtn) {
    if (isStrandedHosts) {
      fixBtn.classList.remove("hidden");
      fixBtn.textContent = "Dọn dẹp hosts →";
      fixBtn.onclick = () => run(fixBtn, restoreHosts);
    } else if (!caTrusted) {
      fixBtn.classList.remove("hidden");
      fixBtn.textContent = "Cài đặt Root CA →";
      fixBtn.onclick = promptAutoSetupCa;
    } else {
      fixBtn.classList.add("hidden");
    }
  }
}

// ── logs ─────────────────────────────────────────────────────────────────────

async function refreshLog() {
  try {
    const lines = await invoke("daemon_log", { lines: LOG_LINES });
    $("daemon-log").textContent = lines.length ? lines.join("\n") : "(chưa có dữ liệu log)";
  } catch (error) {
    console.error("Reading daemon log", error);
  }
}

async function copyDaemonLog() {
  const logText = $("daemon-log").textContent;
  try {
    await navigator.clipboard.writeText(logText);
    toast("Đã sao chép toàn bộ log vào clipboard! ✓", "ok");
  } catch (e) {
    toast("Không thể sao chép: " + e, "error");
  }
}

// ── accounts ─────────────────────────────────────────────────────────────────

function shortTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const day = String(date.getDate()).padStart(2, "0");
  const month = date.toLocaleString(undefined, { month: "short" });
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  return `${day} ${month} ${hh}:${mm}`;
}

function creditCell(account) {
  const total = Number.isFinite(account.credit_total) ? account.credit_total : 0;
  const avail = Number.isFinite(account.credit_available) ? account.credit_available : 0;
  return total > 0 ? `${avail.toFixed(1)} / ${total.toFixed(0)} cr` : "—";
}

function actionButton(label, handler, className = "ghost") {
  const button = document.createElement("button");
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", (e) => run(e.currentTarget, handler));
  return button;
}

function accountRow(account) {
  const tr = document.createElement("tr");
  if (account.is_active) tr.classList.add("row-active");

  // Column 1: Label + sub
  const tdLabel = document.createElement("td");
  tdLabel.className = "cell-label";
  const nameRow = document.createElement("div");
  nameRow.style.display = "flex";
  nameRow.style.alignItems = "center";
  nameRow.style.gap = "6px";

  const name = document.createElement("span");
  name.className = "cell-name";
  name.textContent = account.label;
  nameRow.append(name);

  if (account.is_active) {
    const liveTag = document.createElement("span");
    liveTag.className = "badge-live-tag";
    liveTag.textContent = "LIVE";
    liveTag.title = "Kiro IDE hiện đang sử dụng tài khoản này";
    nameRow.append(liveTag);
  }
  tdLabel.append(nameRow);

  const sub = document.createElement("span");
  sub.className = "cell-sub";
  sub.textContent = [account.region, account.auth_method].filter(Boolean).join(" · ") || "Kiro SSO";
  tdLabel.append(sub);

  // Column 2: Email
  const tdEmail = document.createElement("td");
  tdEmail.textContent = account.email || "—";

  // Column 3: Status
  const tdStatus = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = "badge";
  let statusText = "Sẵn sàng";
  let statusState = account.status || "normal";
  if (account.is_active) {
    statusText = "Đang dùng ✓";
    statusState = "active";
  } else if (account.status === "exhausted") {
    statusText = "Hết ngạch ⚠️";
    statusState = "exhausted";
  } else if (account.status === "expired") {
    statusText = "Hết hạn ❌";
    statusState = "expired";
  }
  badge.dataset.state = statusState;
  badge.textContent = statusText;
  tdStatus.append(badge);

  // Column 4: Credits (with progress bar)
  const tdCredits = document.createElement("td");
  const total = Number.isFinite(account.credit_total) ? account.credit_total : 0;
  const avail = Number.isFinite(account.credit_available) ? account.credit_available : 0;
  const used = Number.isFinite(account.credit_used)
    ? account.credit_used
    : Math.max(0, total - avail);

  if (total > 0) {
    const pct = Math.min(100, Math.max(0, (avail / total) * 100));
    let barClass = "";
    if (avail <= 0) barClass = "empty";
    else if (pct < 20) barClass = "low";

    const box = document.createElement("div");
    box.className = "table-credits-box";
    box.title = `Khả dụng (còn lại): ${avail.toFixed(1)} cr | Đã dùng: ${used.toFixed(1)} cr | Tổng: ${total.toFixed(0)} cr`;
    box.innerHTML = `
      <div class="table-progress-wrap">
        <div class="table-progress-bar ${barClass}" style="width: ${pct}%"></div>
      </div>
      <div class="table-credits-nums">
        <span class="table-credits-avail">Còn: <strong>${avail.toFixed(1)}</strong> cr</span>
        <span class="table-credits-used">Dùng: ${used.toFixed(1)} / ${total.toFixed(0)}</span>
      </div>
    `;
    tdCredits.append(box);
  } else {
    const na = document.createElement("span");
    na.className = "cell-sub";
    na.textContent = "Chưa có dữ liệu";
    tdCredits.append(na);
  }

  // Column 5: Reset date
  const tdReset = document.createElement("td");
  tdReset.textContent = shortTime(account.cycle_reset_at);

  // Column 6: Actions
  const tdActions = document.createElement("td");
  tdActions.className = "row-actions";

  if (account.is_active) {
    const btnActive = document.createElement("button");
    btnActive.className = "btn ghost small-btn btn-action-active-now";
    btnActive.disabled = true;
    btnActive.textContent = "Đang dùng ✓";
    tdActions.append(btnActive);
  } else {
    tdActions.append(actionButton("⚡ Kích hoạt", () => switchTo(account.label), "btn secondary small-btn"));
  }

  if (account.status === "active" || account.status === "normal") {
    tdActions.append(actionButton("⚠️ Hết ngạch", () => markExhausted(account.label), "btn ghost small-btn"));
  }

  tdActions.append(
    actionButton("📤 Xuất", () => exportAccount(account.label), "btn ghost small-btn"),
    actionButton("🗑️", () => removeAccount(account.label), "btn ghost danger-text small-btn")
  );

  tr.title = `Lần dùng cuối: ${shortTime(account.last_used_at)}`;
  tr.append(tdLabel, tdEmail, tdStatus, tdCredits, tdReset, tdActions);
  return tr;
}

function applyAccountsFilterAndSort() {
  if (!accounts || !accounts.accounts) return;

  const query = (currentAcctSearch || "").trim().toLowerCase();
  let list = accounts.accounts.slice();

  // 1. Filter by status pill
  if (currentAcctFilter === "ready") {
    list = list.filter((a) => a.status !== "exhausted" && a.status !== "expired");
  } else if (currentAcctFilter === "exhausted") {
    list = list.filter((a) => a.status === "exhausted" || a.status === "expired");
  }

  // 2. Filter by search query (label, email, region)
  if (query) {
    list = list.filter(
      (a) =>
        (a.label && a.label.toLowerCase().includes(query)) ||
        (a.email && a.email.toLowerCase().includes(query)) ||
        (a.region && a.region.toLowerCase().includes(query))
    );
  }

  // 3. Sort
  if (currentAcctSort === "credits-desc") {
    list.sort((a, b) => (b.credit_available || 0) - (a.credit_available || 0));
  } else if (currentAcctSort === "reset-asc") {
    list.sort((a, b) => {
      if (!a.cycle_reset_at) return 1;
      if (!b.cycle_reset_at) return -1;
      return new Date(a.cycle_reset_at).getTime() - new Date(b.cycle_reset_at).getTime();
    });
  } else if (currentAcctSort === "name-asc") {
    list.sort((a, b) => a.label.localeCompare(b.label));
  }
  // "default": keeps server order (already sorted by credit_available desc)

  const body = $("accounts-body");
  if (!body) return;

  if (list.length === 0 && accounts.accounts.length > 0) {
    body.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px; color: var(--muted);">🔍 Không tìm thấy tài khoản phù hợp với từ khóa hoặc bộ lọc.</td></tr>`;
  } else {
    body.replaceChildren(...list.map(accountRow));
  }
}

function renderAccounts(view) {
  accounts = view;
  const totalCount = view.accounts.length;
  const readyCount = view.accounts.filter((a) => a.status !== "exhausted" && a.status !== "expired").length;
  const exhaustedCount = view.accounts.filter((a) => a.status === "exhausted" || a.status === "expired").length;
  const totalAvailableCredits = view.accounts.reduce(
    (sum, a) => sum + (Number.isFinite(a.credit_available) ? a.credit_available : 0),
    0
  );

  // 1. Update KPI Statistics
  if ($("acct-stat-total")) $("acct-stat-total").textContent = String(totalCount);
  if ($("acct-stat-credits")) {
    $("acct-stat-credits").textContent = totalCount > 0 ? `${totalAvailableCredits.toFixed(1)} cr` : "—";
  }
  if ($("acct-stat-health")) {
    if (totalCount === 0) {
      $("acct-stat-health").textContent = "Chưa có tài khoản";
      $("acct-stat-health").style.color = "var(--muted)";
    } else if (readyCount === 0) {
      $("acct-stat-health").textContent = "⚠️ Hết ngạch";
      $("acct-stat-health").style.color = "#dc2626";
    } else {
      $("acct-stat-health").textContent = `${readyCount}/${totalCount} Sẵn sàng`;
      $("acct-stat-health").style.color = "#16a34a";
    }
  }

  // Filter pills counts
  if ($("acct-count-all")) $("acct-count-all").textContent = String(totalCount);
  if ($("acct-count-ready")) $("acct-count-ready").textContent = String(readyCount);
  if ($("acct-count-exhausted")) $("acct-count-exhausted").textContent = String(exhaustedCount);

  // 2. Active Account Spotlight & Dashboard Card 2
  const activeAcc = view.accounts.find((a) => a.is_active) || view.accounts[0];

  if ($("acct-stat-active")) $("acct-stat-active").textContent = activeAcc?.label || "Chưa có";

  if (!activeAcc || totalCount === 0) {
    $("dash-account-status").textContent = "chưa có";
    $("dash-account-status").dataset.state = "unknown";
    $("dash-account-label").textContent = "Chưa có tài khoản";
    $("dash-account-email").textContent = "Nhập tài khoản từ tab Accounts";
    $("dash-credits-text").textContent = "— / —";
    $("dash-credits-bar").style.width = "0%";
    $("dash-credits-left").textContent = "chưa có dữ liệu";
    $("dash-resets-text").textContent = "Đặt lại: —";
    $("dash-auto-switch").disabled = true;

    $("accounts-active-spotlight")?.classList.add("hidden");
  } else {
    $("dash-account-status").textContent = activeAcc.status;
    $("dash-account-status").dataset.state = activeAcc.status;
    $("dash-account-label").textContent = (activeAcc.is_active ? "► " : "") + activeAcc.label;
    $("dash-account-email").textContent = activeAcc.email || "—";

    const total = activeAcc.credit_total > 0 ? activeAcc.credit_total : 0;
    const used = activeAcc.credit_used > 0 ? activeAcc.credit_used : 0;
    const avail = activeAcc.credit_available > 0 ? activeAcc.credit_available : 0;
    const pct = total > 0 ? Math.min(100, Math.max(0, (avail / total) * 100)) : 0;

    const creditTip = `Khả dụng (còn lại): ${avail.toFixed(1)} cr | Đã dùng: ${used.toFixed(1)} cr | Tổng: ${total.toFixed(0)} cr`;

    $("dash-credits-text").textContent = total > 0 ? `${avail.toFixed(1)} / ${total.toFixed(0)} cr` : "—";
    const dashBar = $("dash-credits-bar");
    if (dashBar) {
      dashBar.style.width = `${pct}%`;
      if (avail <= 0) {
        dashBar.style.background = "#ef4444";
      } else if (pct < 20) {
        dashBar.style.background = "#f59e0b";
      } else {
        dashBar.style.background = "linear-gradient(90deg, #10b981, #059669)";
      }
    }
    const dashWrap = $("dash-credits-bar-wrap");
    if (dashWrap) dashWrap.title = creditTip;

    $("dash-credits-left").textContent = total > 0
      ? `Đã dùng: ${used.toFixed(1)} cr (${(100 - pct).toFixed(0)}%)`
      : "chưa có dữ liệu";
    $("dash-resets-text").textContent = `Đặt lại: ${shortTime(activeAcc.cycle_reset_at)}`;
    $("dash-auto-switch").disabled = false;

    // Accounts tab spotlight
    const spotlight = $("accounts-active-spotlight");
    if (spotlight) {
      spotlight.classList.remove("hidden");
      if ($("spotlight-name")) $("spotlight-name").textContent = activeAcc.label;
      if ($("spotlight-meta")) {
        $("spotlight-meta").textContent =
          [activeAcc.region, activeAcc.auth_method].filter(Boolean).join(" • ") || "Kiro SSO";
      }
      if ($("spotlight-email")) $("spotlight-email").textContent = activeAcc.email || "—";
      if ($("spotlight-credits-val")) {
        $("spotlight-credits-val").textContent = total > 0 ? `${avail.toFixed(1)} / ${total.toFixed(0)} cr` : "—";
      }
      const spotBar = $("spotlight-progress-bar");
      if (spotBar) {
        spotBar.style.width = `${pct}%`;
        if (avail <= 0) {
          spotBar.style.background = "#ef4444";
        } else if (pct < 20) {
          spotBar.style.background = "#f59e0b";
        } else {
          spotBar.style.background = "linear-gradient(90deg, #10b981, #059669)";
        }
      }
      const spotWrap = $("spotlight-progress-bar-bg");
      if (spotWrap) spotWrap.title = creditTip;

      if ($("spotlight-credits-percent")) {
        $("spotlight-credits-percent").textContent = total > 0
          ? `Còn ${pct.toFixed(0)}% · Đã dùng: ${used.toFixed(1)} cr`
          : "0%";
      }
      if ($("spotlight-reset-time")) {
        $("spotlight-reset-time").textContent = `Đặt lại: ${shortTime(activeAcc.cycle_reset_at)}`;
      }
    }
  }

  // 3. Render Table or Empty State
  $("accounts-empty")?.classList.toggle("hidden", totalCount > 0);
  $("accounts-table")?.classList.toggle("hidden", totalCount === 0);

  applyAccountsFilterAndSort();
}

async function refreshAccounts() {
  try {
    renderAccounts(await invoke("get_accounts"));
  } catch (error) {
    fail("Đọc danh sách tài khoản", error);
  }
}

function syncImport() {
  const shown = $("import-path");
  shown.textContent = importPath ?? "chưa chọn thư mục";
  shown.title = importPath ?? "";
  const go = $("import-go");
  go.disabled = !importPath;
  go.dataset.locked = String(!importPath);
}

async function pickImportFolder() {
  const picked = await open({ directory: true, multiple: false, title: "Chọn thư mục tài khoản Kiro" });
  importPath = typeof picked === "string" ? picked : null;
  syncImport();
}

async function importAccount() {
  if (!importPath) return;
  const label = $("import-label").value.trim();
  const view = await invoke("import_account", { path: importPath, label: label || null });
  renderAccounts(view);
  $("import-label").value = "";
  importPath = null;
  syncImport();
  toast(`Đã nhập tài khoản thành công. Danh sách có ${view.total} tài khoản.`, "ok");
}

async function importCurrentAccount() {
  try {
    const view = await invoke("import_current_kiro_account");
    renderAccounts(view);
    toast(`Đã nhập tài khoản Kiro đang hoạt động! Danh sách có ${view.total} tài khoản.`, "ok");
  } catch (error) {
    fail("Nhập tài khoản Kiro hiện tại", error);
  }
}

async function switchTo(label) {
  renderAccounts(await invoke("switch_account", { label }));
  toast(`Đã chuyển Kiro sang '${label}' — Hãy khởi động lại Kiro IDE để áp dụng!`, "ok");
}

async function markExhausted(label) {
  const ok = await confirm(
    `Đánh dấu tài khoản '${label}' là đã hết hạn mức (Exhausted)? Hệ thống sẽ không tự động chuyển vào tài khoản này cho đến chu kỳ kế tiếp.`,
    {
      title: "Xác nhận hết hạn ngạch",
      kind: "warning",
    }
  );
  if (!ok) return;

  const [view, message] = await invoke("mark_exhausted", { label });
  renderAccounts(view);
  toast(message ?? `Đã đánh dấu '${label}' hết hạn mức.`, "ok");
}

async function exportAccount(label) {
  const outDir = await open({ directory: true, title: "Chọn thư mục xuất tài khoản" });
  if (typeof outDir !== "string") return;
  const written = await invoke("export_account", { label, outDir });
  toast(`Đã xuất '${label}' ra ${written}\nThư mục này chứa refresh token đang hoạt động — hãy bảo mật cẩn thận.`, "ok");
}

async function removeAccount(label) {
  const ok = await confirm(`Xóa tài khoản '${label}' khỏi danh sách?`, {
    title: "Xóa tài khoản",
    kind: "warning",
  });
  if (!ok) return;
  renderAccounts(await invoke("remove_account", { label }));
  toast(`Đã xóa '${label}'.`, "ok");
}

async function autoSwitch() {
  const [view, label] = await invoke("auto_switch_account");
  renderAccounts(view);
  toast(`Đã tự động chuyển Kiro sang '${label}' — Hãy khởi động lại Kiro IDE để áp dụng!`, "ok");
}

async function refreshUsage() {
  const [view, notes] = await invoke("refresh_accounts_usage");
  renderAccounts(view);
  if (notes.length) toast(`Đã làm mới hạn mức với ghi chú:\n${notes.join("\n")}`);
  else toast("Đã làm mới hạn mức tài khoản.", "ok");
}

// ── plumbing ─────────────────────────────────────────────────────────────────

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
      button.disabled = button.dataset.locked === "true";
      button.classList.remove("busy");
    }
  }
}

function bind() {
  // Navigation tabs
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => showView(tab.dataset.view));
  }

  // Dashboard shortcuts
  $("dash-goto-router")?.addEventListener("click", () => showView("settings"));
  $("dash-goto-accounts")?.addEventListener("click", () => showView("accounts"));
  $("dash-auto-switch")?.addEventListener("click", (e) => run(e.currentTarget, autoSwitch));

  // Onboarding shortcuts
  $("btn-goto-provider")?.addEventListener("click", () => showView("settings"));
  $("btn-quick-ca")?.addEventListener("click", () => run($("btn-quick-ca"), promptAutoSetupCa));

  // Presets in Settings view
  for (const card of document.querySelectorAll(".preset-card")) {
    card.addEventListener("click", () => applyPreset(card.dataset.preset));
  }

  // Test Connection button
  $("btn-test-connection")?.addEventListener("click", testProviderConnection);

  // Quick chips for model inputs
  for (const chip of document.querySelectorAll(".chip-btn")) {
    chip.addEventListener("click", () => {
      const targetId = chip.closest(".chips-list")?.dataset.target;
      if (targetId && $(targetId)) {
        $(targetId).value = chip.dataset.val;
        $(targetId).dispatchEvent(new Event("input"));
        setDirty(true);
      }
    });
  }

  // Model filter search & pills
  $("model-filter-input")?.addEventListener("input", (e) => filterModels(e.target.value, currentFamilyFilter));

  for (const pill of document.querySelectorAll(".model-filter-pills .filter-pill")) {
    pill.addEventListener("click", () => {
      for (const p of document.querySelectorAll(".model-filter-pills .filter-pill")) p.classList.remove("active");
      pill.classList.add("active");
      filterModels($("model-filter-input")?.value, pill.dataset.family);
    });
  }

  // Custom model mappings
  $("btn-add-custom-model")?.addEventListener("click", addCustomMapping);
  $("custom-provider")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addCustomMapping();
  });

  // Settings Action Bar buttons
  $("btn-reset-settings")?.addEventListener("click", resetSettings);
  $("save-all-settings")?.addEventListener("click", (e) => run(e.currentTarget, saveAllSettings));

  // Settings system controls
  $("set-ca-setup")?.addEventListener("click", (e) => run(e.currentTarget, promptAutoSetupCa));
  $("set-restore-hosts")?.addEventListener("click", (e) => run(e.currentTarget, restoreHosts));

  // Input change detection for dirty indicator
  $("base-url")?.addEventListener("input", () => setDirty(true));
  $("api-key")?.addEventListener("input", () => setDirty(true));
  $("slot-auto")?.addEventListener("input", () => {
    updatePipelineSummary();
    setDirty(true);
  });
  $("slot-simple")?.addEventListener("input", () => {
    updatePipelineSummary();
    setDirty(true);
  });
  $("default-model")?.addEventListener("input", () => {
    updatePipelineSummary();
    setDirty(true);
  });

  // API Key visibility toggle
  $("toggle-key-visibility")?.addEventListener("click", toggleKeyVisibility);

  // Proxy toggle & Elevation
  $("proxy-toggle")?.addEventListener("change", handleToggleProxyChange);

  $("elevation-cancel")?.addEventListener("click", () => {
    closeElevationModal();
    $("proxy-toggle").checked = Boolean(daemon?.state === "running");
  });
  $("elevation-confirm")?.addEventListener("click", async () => {
    const action = pendingElevationAction;
    closeElevationModal();
    if (action) await action();
  });

  // Hosts recovery
  $("btn-restore-hosts")?.addEventListener("click", () => run($("btn-restore-hosts"), restoreHosts));
  $("diag-restore-hosts")?.addEventListener("click", () => run($("diag-restore-hosts"), restoreHosts));

  // CA Setup in Diagnostics
  $("ca-setup")?.addEventListener("click", (e) => run(e.currentTarget, promptAutoSetupCa));

  // Diagnostics Log
  $("btn-copy-log")?.addEventListener("click", copyDaemonLog);
  $("btn-refresh-log")?.addEventListener("click", (e) => run(e.currentTarget, refreshLog));

  // Accounts
  $("accounts-import-current")?.addEventListener("click", (e) => run(e.currentTarget, importCurrentAccount));
  $("btn-empty-import")?.addEventListener("click", (e) => run(e.currentTarget, importCurrentAccount));
  $("accounts-auto")?.addEventListener("click", (e) => run(e.currentTarget, autoSwitch));
  $("accounts-refresh")?.addEventListener("click", (e) => run(e.currentTarget, refreshUsage));
  $("import-pick")?.addEventListener("click", (e) => run(e.currentTarget, pickImportFolder));
  $("import-go")?.addEventListener("click", (e) => run(e.currentTarget, importAccount));
  $("import-label")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !$("import-go").disabled) $("import-go").click();
  });

  // Accounts search, filter pills, and sort select
  $("acct-search-input")?.addEventListener("input", (e) => {
    currentAcctSearch = e.target.value;
    applyAccountsFilterAndSort();
  });

  for (const pill of document.querySelectorAll(".acct-filter-pills .filter-pill")) {
    pill.addEventListener("click", () => {
      for (const p of document.querySelectorAll(".acct-filter-pills .filter-pill")) p.classList.remove("active");
      pill.classList.add("active");
      currentAcctFilter = pill.dataset.acctFilter;
      applyAccountsFilterAndSort();
    });
  }

  $("acct-sort-select")?.addEventListener("change", (e) => {
    currentAcctSort = e.target.value;
    applyAccountsFilterAndSort();
  });

  // Keyboard Enter shortcuts
  $("api-key")?.addEventListener("keydown", (e) => e.key === "Enter" && $("save-all-settings").click());
  $("slot-auto")?.addEventListener("keydown", (e) => e.key === "Enter" && $("save-all-settings").click());
  $("slot-simple")?.addEventListener("keydown", (e) => e.key === "Enter" && $("save-all-settings").click());
  $("default-model")?.addEventListener("keydown", (e) => e.key === "Enter" && $("save-all-settings").click());
}

async function boot() {
  bind();
  showView("dashboard");
  await Promise.all([refreshConfig(), refreshCa(), refreshDaemon(), refreshLog(), refreshAccounts()]);

  try {
    await listen("proxy-status-changed", (event) => renderDaemon(event.payload));
  } catch (error) {
    console.warn("event bridge unavailable", error);
  }

  setInterval(refreshDaemon, POLL_STATUS_MS);
  setInterval(refreshLog, POLL_LOG_MS);
}

boot();
