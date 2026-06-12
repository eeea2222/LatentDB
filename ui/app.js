const root = document.getElementById("root");

const DEFAULT_API = "http://127.0.0.1:8080";
const state = {
  apiBase: localStorage.getItem("latentdb_api") || DEFAULT_API,
  token: localStorage.getItem("latentdb_token") || "",
  route: location.hash.replace("#/", "") || "overview",
  booted: false,
  loading: false,
  apiReady: false,
  error: "",
  me: null,
  objectTypes: [],
  dashboards: [],
  reports: [],
  approvals: [],
  aiCapabilities: null,
  builderDrafts: [],
  builderTemplates: [],
  builderValidation: null,
  builderPublished: null,
  builderDefinition: null,
  accel: null,
  currentObject: localStorage.getItem("latentdb_object") || "",
  currentSearch: "",
  recordPage: null,
  selectedRecord: null,
  selectedObject: null,
  reportResult: null,
  agentAnswer: null,
  drawer: null
};

const navGroups = [
  {
    label: "Operate",
    items: [
      ["overview", "O", "Overview"],
      ["records", "R", "Records"],
      ["reports", "P", "Reports"],
      ["approvals", "A", "Approvals"]
    ]
  },
  {
    label: "Assist",
    items: [
      ["agents", "I", "AI Agents"],
      ["actions", "D", "Action Planner"]
    ]
  },
  {
    label: "Admin",
    items: [
      ["builder", "B", "Builder"],
      ["schema", "S", "Schema"],
      ["system", "Y", "System"]
    ]
  }
];

const FALLBACK_AI_CAPABILITIES = {
  bi_ask: { key: "bi_ask", label: "BI question", endpoint: "/v1/ai/bi/ask" },
  actions: [
    { key: "dry_run", label: "Dry-run action", endpoint: "/v1/ai/actions/dry-run" },
    { key: "execute", label: "Execute approved action", endpoint: "/v1/ai/actions/execute" }
  ],
  agents: [
  {
    key: "finance",
    label: "Finance",
    action: "Cashflow risk",
    endpoint: "/v1/ai/agents/finance/cashflow-risk",
    modules: ["finance", "erp"],
    object_hints: ["invoice", "payment", "budget", "account", "bill"]
  },
  {
    key: "procurement",
    label: "Procurement",
    action: "Supply risk",
    endpoint: "/v1/ai/agents/procurement/low-stock",
    modules: ["procurement", "inventory", "scm"],
    object_hints: ["purchase", "vendor", "product", "inventory", "warehouse", "receipt"]
  },
  {
    key: "sales",
    label: "Sales",
    action: "Pipeline risk",
    endpoint: "/v1/ai/agents/sales/deal-risk",
    modules: ["crm", "sales"],
    object_hints: ["deal", "lead", "contact", "opportunity", "account"]
  }
  ]
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function pretty(value) {
  return esc(JSON.stringify(value, null, 2));
}

function compact(value, max = 80) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (!text) return "";
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function moneyMinor(value) {
  const n = Number(value || 0) / 100;
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(n);
}

function intFmt(value) {
  return new Intl.NumberFormat("en-US").format(Number(value || 0));
}

function titleize(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function tenantModules() {
  const modules = new Set();
  state.objectTypes.forEach((object) => {
    if (object.module) modules.add(object.module);
  });
  state.builderTemplates.forEach((template) => modules.add(template.key));
  return Array.from(modules).sort();
}

function objectLabel(object) {
  return object?.label_plural || object?.label || object?.key || "Records";
}

function objectByKey(key = state.currentObject) {
  return state.objectTypes.find((object) => object.key === key) || null;
}

function defaultObjectKey() {
  return state.objectTypes[0]?.key || "";
}

function availableAgents() {
  if (!state.objectTypes.length) return [];
  return aiCapabilities().agents.filter((agent) => {
    return state.objectTypes.some((object) => {
      const module = String(object.module || "").toLowerCase();
      const key = String(object.key || "").toLowerCase();
      const modules = agent.modules || [];
      const hints = agent.object_hints || [];
      return modules.includes(module) || hints.some((hint) => key.includes(hint));
    });
  });
}

function aiCapabilities() {
  return state.aiCapabilities || FALLBACK_AI_CAPABILITIES;
}

function aiActionEndpoint(key) {
  return aiCapabilities().actions?.find((action) => action.key === key)?.endpoint;
}

function primaryAgent() {
  return availableAgents()[0] || null;
}

function defaultBiQuestion() {
  const labels = state.objectTypes.slice(0, 3).map(objectLabel);
  if (!labels.length) return "What should I review first in this tenant?";
  return `What risks or anomalies are visible across ${labels.join(", ")}?`;
}

function generatedRecordPayload(object) {
  const payload = {};
  const fields = (object?.fields || []).filter((field) => !field.restricted);
  const prioritized = [
    ...fields.filter((field) => field.required || field.display),
    ...fields.filter((field) => !field.required && !field.display)
  ];
  prioritized.slice(0, 6).forEach((field) => {
    payload[field.key] = sampleValue(field);
  });
  return payload;
}

function statusClass(value) {
  const s = String(value || "").toLowerCase();
  if (["paid", "won", "approved", "received", "closed", "done", "active", "ready"].includes(s)) return "green";
  if (["draft", "submitted", "requested", "manager_review", "finance_review", "pending", "open", "proposal", "negotiation"].includes(s)) return "amber";
  if (["lost", "rejected", "cancelled", "at_risk", "urgent", "expired"].includes(s)) return "red";
  if (["qualified", "prospecting", "ordered", "renewal_review"].includes(s)) return "blue";
  return "neutral";
}

async function api(path, options = {}) {
  const headers = { "content-type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  const res = await fetch(`${state.apiBase}${path}`, { ...options, headers });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(data?.error?.message || data?.message || res.statusText);
  return data;
}

async function boot() {
  bindHash();
  render();
  await checkApi();
  if (state.token) {
    try {
      await loadBase();
      await hydrateRoute();
    } catch (err) {
      state.error = err.message;
      state.token = "";
      localStorage.removeItem("latentdb_token");
    }
  }
  state.booted = true;
  render();
}

function bindHash() {
  window.addEventListener("hashchange", async () => {
    state.route = location.hash.replace("#/", "") || "overview";
    state.error = "";
    state.selectedRecord = null;
    render();
    await hydrateRoute();
    render();
  });
}

async function checkApi() {
  try {
    const ready = await fetch(`${state.apiBase}/readyz`).then((r) => r.json());
    state.apiReady = ready.status === "ready";
  } catch {
    state.apiReady = false;
  }
}

async function loadBase() {
  const [me, objectTypes, dashboards, reports, capabilities] = await Promise.all([
    api("/v1/auth/me"),
    api("/v1/object-types"),
    api("/v1/dashboards"),
    api("/v1/reports"),
    api("/v1/ai/capabilities").catch(() => null)
  ]);
  state.me = me;
  state.objectTypes = objectTypes;
  state.dashboards = dashboards;
  state.reports = reports;
  state.aiCapabilities = capabilities;
  if (!state.objectTypes.some((o) => o.key === state.currentObject)) {
    state.currentObject = defaultObjectKey();
  }
  state.selectedObject = objectByKey();
}

async function hydrateRoute() {
  if (!state.token || !state.me) return;
  if (state.route === "overview") await loadOverviewData();
  if (state.route === "records") await loadRecords();
  if (state.route === "reports" && state.reports[0]?.key) await loadReport(state.reports[0].key);
  if (state.route === "approvals") await loadApprovals();
  if (state.route === "builder") await loadBuilder();
  if (state.route === "schema") state.selectedObject = state.objectTypes.find((o) => o.key === state.currentObject) || state.objectTypes[0];
  if (state.route === "system") await loadSystem();
}

async function login(event) {
  event.preventDefault();
  state.error = "";
  const form = new FormData(event.target);
  state.apiBase = form.get("apiBase").trim() || DEFAULT_API;
  localStorage.setItem("latentdb_api", state.apiBase);
  try {
    const res = await fetch(`${state.apiBase}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        tenant: form.get("tenant"),
        email: form.get("email"),
        password: form.get("password")
      })
    }).then(async (r) => {
      const data = await r.json();
      if (!r.ok) throw new Error(data?.error?.message || r.statusText);
      return data;
    });
    state.token = res.token;
    localStorage.setItem("latentdb_token", state.token);
    await checkApi();
    await loadBase();
    location.hash = "#/overview";
    await hydrateRoute();
  } catch (err) {
    state.error = err.message;
  }
  render();
}

async function logout() {
  try { await api("/v1/auth/logout", { method: "POST", body: "{}" }); } catch {}
  localStorage.removeItem("latentdb_token");
  state.token = "";
  state.me = null;
  state.error = "";
  render();
}

function navigate(route) {
  location.hash = `#/${route}`;
}

function render() {
  if (!state.token || !state.me) {
    root.innerHTML = loginView();
    document.querySelector("#loginForm")?.addEventListener("submit", login);
    return;
  }
  root.innerHTML = shellView();
  attachRouteEvents();
}

function loginView() {
  return `
    <div class="login-wrap">
      <section class="login-panel">
        <div class="brand" style="padding:0;border:0;height:auto;margin-bottom:34px">
          <div class="brand-mark">L</div>
          <div class="brand-title"><strong>LatentDB</strong><span>Operations Console</span></div>
        </div>
        <form id="loginForm" class="stack">
          <div>
            <h1>Sign in</h1>
        <p>Connect to a configured LatentDB tenant.</p>
          </div>
          <div><label>API URL</label><input name="apiBase" value="${esc(state.apiBase)}"></div>
          <div class="form-grid" style="grid-template-columns:1fr 1fr">
            <div><label>Tenant</label><input name="tenant" autocomplete="organization" placeholder="tenant-slug"></div>
            <div><label>Email</label><input name="email" type="email" autocomplete="username" placeholder="admin@company.test"></div>
          </div>
          <div><label>Password</label><input name="password" type="password" autocomplete="current-password"></div>
          <button class="primary" type="submit">Sign in</button>
          ${state.error ? `<p class="error">${esc(state.error)}</p>` : ""}
        </form>
      </section>
      <section class="login-context">
        <div class="page-title">
          <h1>Tenant data, workflows, analytics, and AI in one console.</h1>
          <p>This local UI is backed by the Rust API running on your machine. It is designed as an operator surface, not a landing page.</p>
        </div>
        <div class="feature-list">
          ${[
            ["Permission-aware data", "Browse object schemas and tenant-scoped records through the API."],
            ["Operational analytics", "Run saved reports and inspect dashboard cards."],
            ["Approval workflows", "Review pending approval-gated transitions."],
            ["Grounded AI agents", "Ask available tenant agents and BI with citations."],
            ["Action safety", "Dry-run agent actions before approved execution."],
            ["System status", "Check acceleration backend availability and session context."]
          ].map(([a, b]) => `<div class="feature-item"><h2>${a}</h2><p>${b}</p></div>`).join("")}
        </div>
      </section>
    </div>`;
}

function shellView() {
  return `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-mark">L</div>
          <div class="brand-title"><strong>LatentDB</strong><span>Operations Console</span></div>
        </div>
        <div class="commandbar">
          <input id="globalSearch" placeholder="Search tenant records, schemas, reports" value="${esc(state.currentSearch)}">
          <button id="globalSearchBtn">Search</button>
          <span class="status-pill ${state.apiReady ? "green" : "red"}">${state.apiReady ? "API ready" : "API offline"}</span>
        </div>
        <div class="top-actions">
          <span class="pill mono">${esc(state.me.tenant_id.slice(0, 8))}</span>
          <button class="icon-button" title="Notifications">!</button>
          <button id="refreshBtn">Refresh</button>
          <button id="logoutBtn">Logout</button>
        </div>
      </header>
      <aside class="sidebar">${sidebarView()}</aside>
      <main class="main">${routeView()}</main>
      <aside class="inspector">${inspectorView()}</aside>
      ${state.drawer ? drawerView() : ""}
    </div>`;
}

function sidebarView() {
  return navGroups.map((group) => `
    <div class="nav-section">
      <div class="nav-label">${esc(group.label)}</div>
      ${group.items.map(([key, icon, label]) => `
        <button class="nav-item ${state.route === key ? "active" : ""}" data-route="${key}">
          <span class="nav-icon">${icon}</span>
          <span>${label}</span>
          <span class="nav-count">${navCount(key)}</span>
        </button>`).join("")}
    </div>`).join("");
}

function navCount(key) {
  if (key === "records") return state.objectTypes.length || "";
  if (key === "reports") return state.reports.length || "";
  if (key === "approvals") return state.approvals.length || "";
  if (key === "builder") return state.builderDrafts.length || "";
  return "";
}

function routeView() {
  const views = {
    overview: overviewView,
    records: recordsView,
    reports: reportsView,
    approvals: approvalsView,
    agents: agentsView,
    actions: actionsView,
    builder: builderView,
    schema: schemaView,
    system: systemView
  };
  return (views[state.route] || overviewView)();
}

function pageHead(title, subtitle, actions = "") {
  return `
    <div class="page-head">
      <div class="page-title"><h1>${esc(title)}</h1><p>${esc(subtitle)}</p></div>
      <div class="page-actions">${actions}</div>
    </div>`;
}

function overviewView() {
  const moduleCounts = overviewModuleCounts();
  const primaryObjects = state.objectTypes.slice(0, 5);
  const agent = primaryAgent();
  return `
    <div class="tab-strip">
      <button class="active">Dashboard</button>
      <button data-route="builder">Builder</button>
      <button data-route="records">Records</button>
      <button data-route="reports">Reports</button>
    </div>
    ${pageHead("Command center", "A live summary of the tenant operating model.", `<button id="overviewRefresh">Refresh</button>`)}
    <div class="grid">
      ${metricCard("Object types", state.objectTypes.length, "Metadata-backed business entities")}
      ${metricCard("Reports", state.reports.length, "Saved analytical definitions")}
      ${metricCard("Dashboards", state.dashboards.length, "Configured operator views")}
      ${metricCard("Approvals", state.approvals.length, "Pending approval work")}
      <section class="panel span-8">
        <div class="panel-head"><h2>Tenant objects</h2><button data-route="records">Open records</button></div>
        <div class="panel-table">${primaryObjects.length ? objectSummaryTable(primaryObjects) : `<div class="empty">Install a Builder template or publish an object to populate the operating model.</div>`}</div>
      </section>
      <section class="panel span-4">
        <div class="panel-head"><h2>Module coverage</h2><button data-route="reports">Reports</button></div>
        <div class="panel-body">${miniChart(moduleCounts)}</div>
      </section>
      <section class="panel span-7">
        <div class="panel-head"><h2>Governance flow</h2><button data-route="builder">Open Builder</button></div>
        <div class="panel-body">${governanceFlow()}</div>
      </section>
      <section class="panel span-5">
        <div class="panel-head"><h2>Audit trail</h2><button data-route="approvals">Approvals</button></div>
        <div class="panel-body stack-sm">
          ${activityItem("Builder publish", "Object metadata is validated, audited, and emitted as an event.", "green")}
          ${activityItem("AI visibility", "Sensitive fields stay hidden unless explicitly enabled.", "blue")}
          ${activityItem("Action planner", "Dry-runs never mutate records before approval.", "amber")}
        </div>
      </section>
      <section class="panel span-12">
        <div class="panel-head"><h2>AI brief</h2><button id="primaryAgentRefresh" ${agent ? "" : "disabled"}>${agent ? `Run ${esc(agent.label)}` : "No matching agent"}</button></div>
        <div class="panel-body">${answerBlock(state.agentAnswer, agent ? `Run ${agent.label} to generate a governed brief from tenant records.` : "No built-in agent matches the currently published modules.")}</div>
      </section>
    </div>`;
}

function overviewModuleCounts() {
  const grouped = groupBy(state.objectTypes, (object) => object.module || "custom");
  return Object.entries(grouped)
    .map(([name, objects]) => [name, objects.length])
    .sort(([a], [b]) => a.localeCompare(b));
}

function objectSummaryTable(objects) {
  return `
    <table>
      <thead><tr><th>Object</th><th>Module</th><th>Fields</th><th>AI visible</th><th>State</th></tr></thead>
      <tbody>
        ${objects.map((o) => `
          <tr class="clickable-row" data-object="${esc(o.key)}" data-route="records">
            <td><div class="record-title">${esc(o.label_plural || o.label)}</div><div class="mono muted">${esc(o.key)}</div></td>
            <td>${esc(o.module || "custom")}</td>
            <td>${(o.fields || []).length}</td>
            <td>${(o.fields || []).filter((f) => f.ai_visible).length}</td>
            <td><span class="status-pill green">governed</span></td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function miniChart(moduleCounts) {
  const total = moduleCounts.reduce((sum, [, count]) => sum + count, 0);
  if (total === 0) {
    return `<div class="empty">No published object modules yet. Install a Builder template or publish an object to populate this chart.</div>`;
  }
  const max = Math.max(1, ...moduleCounts.map(([, count]) => count));
  return `<div class="mini-chart">${moduleCounts.map(([name, count]) => `
    <div class="chart-bar" style="height:${32 + (count / max) * 110}px">
      <span>${esc(count)}</span>
      <em>${esc(name.slice(0, 3))}</em>
    </div>`).join("")}</div>`;
}

function governanceFlow() {
  return `
    <div class="flow-map">
      ${["Draft", "Validate", "Publish", "Audit", "Use"].map((step, i) => `
        <div class="flow-step">
          <div class="flow-node ${i === 2 ? "active" : ""}">${esc(step)}</div>
          ${i < 4 ? `<div class="flow-link"></div>` : ""}
        </div>`).join("")}
    </div>
    <p style="margin-top:12px">Dynamic objects become ordinary metadata only after kernel validation. Records, reports, workflows, AI retrieval, and action planning all read the same governed definition.</p>`;
}

function activityItem(title, body, tone) {
  return `
    <div class="activity-item">
      <span class="status-dot ${tone}"></span>
      <div><h3>${esc(title)}</h3><p>${esc(body)}</p></div>
    </div>`;
}

function metricCard(label, value, note) {
  return `
    <section class="panel span-3 metric">
      <div class="metric-label"><span>${esc(label)}</span><span class="pill">live</span></div>
      <div class="metric-value">${esc(intFmt(value))}</div>
      <div class="metric-note">${esc(note)}</div>
    </section>`;
}

function dashboardSummary(dashboard) {
  return `
    <div class="row-between" style="align-items:flex-start">
      <div class="stack-sm">
        <h3>${esc(dashboard.name)}</h3>
        <div>${(dashboard.cards || []).map((c) => `<span class="pill">${esc(c.title || c.report || c.agent)}</span>`).join("")}</div>
      </div>
      <span class="status-pill blue">${(dashboard.cards || []).length} cards</span>
    </div>`;
}

function recordsView() {
  const object = state.objectTypes.find((o) => o.key === state.currentObject);
  const rows = state.recordPage?.items || [];
  const fields = displayFields(object, rows);
  const disabled = object ? "" : "disabled";
  return `
    ${pageHead("Records", "Browse tenant-scoped data with schema-aware columns.", `
      <button id="openCreateDrawer" ${disabled}>New record</button>
      <button id="reloadRecords">Reload</button>
    `)}
    <section class="panel">
      <div class="panel-head">
        <div class="row">
          <select id="objectSelect" style="width:260px" ${disabled}>${state.objectTypes.map((o) => `<option value="${esc(o.key)}" ${o.key === state.currentObject ? "selected" : ""}>${esc(objectLabel(o))}</option>`).join("")}</select>
          <input id="recordSearch" placeholder="Search ${esc(objectLabel(object))}" value="${esc(state.currentSearch)}" style="width:320px" ${disabled}>
          <button id="recordSearchBtn" ${disabled}>Search</button>
        </div>
        <span class="pill">${state.recordPage ? intFmt(state.recordPage.total) : "0"} total</span>
      </div>
      <div class="panel-table">
        ${object ? (rows.length ? recordTable(object, rows, fields) : `<div class="empty">No records matched this query.</div>`) : `<div class="empty">Publish an object or install a Builder template before creating records.</div>`}
      </div>
    </section>`;
}

function displayFields(object, rows) {
  const defined = (object?.fields || []).map((f) => f.key).slice(0, 5);
  if (defined.length) return defined;
  const keys = new Set();
  rows.forEach((r) => Object.keys(r.data || {}).forEach((k) => keys.add(k)));
  return Array.from(keys).slice(0, 5);
}

function recordTable(object, rows, fields) {
  return `
    <table>
      <thead><tr><th>Record</th>${fields.map((f) => `<th>${esc(fieldLabel(object, f))}</th>`).join("")}<th>Status</th></tr></thead>
      <tbody>
        ${rows.map((r) => `
          <tr class="clickable-row" data-record-id="${esc(r.id)}">
            <td><div class="record-title">${esc(recordTitle(object, r))}</div><div class="mono muted">${esc(r.id)}</div></td>
            ${fields.map((f) => `<td>${cellValue(r.data?.[f], f)}</td>`).join("")}
            <td>${statusBadge(r.workflow_state || r.data?.status || r.data?.stage || r.data?.priority)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function fieldLabel(object, key) {
  return object?.fields?.find((f) => f.key === key)?.label || key;
}

function recordTitle(object, record) {
  const field = object?.display_field;
  return record.data?.[field] || record.data?.name || record.data?.number || record.data?.title || record.id.slice(0, 8);
}

function cellValue(value, key) {
  if (value === null || value === undefined) return `<span class="muted">-</span>`;
  if (key.includes("amount") || key.includes("cost") || key.includes("price") || key.includes("salary") || key === "value") return esc(moneyMinor(value));
  if (typeof value === "object") return `<span class="json-cell mono">${esc(compact(value, 90))}</span>`;
  if (String(key).includes("status") || String(key).includes("stage") || String(key).includes("priority")) return statusBadge(value);
  return esc(compact(value, 90));
}

function statusBadge(value) {
  if (!value) return `<span class="status-pill neutral">none</span>`;
  return `<span class="status-pill ${statusClass(value)}">${esc(value)}</span>`;
}

function reportsView() {
  const disabled = state.reports.length ? "" : "disabled";
  return `
    ${pageHead("Reports", "Run saved analytics against the kernel.", `<button id="runSelectedReport" ${disabled}>Run selected</button>`)}
    <div class="grid">
      <section class="panel span-4">
        <div class="panel-head"><h2>Saved reports</h2><span class="pill">${state.reports.length}</span></div>
        <div class="panel-body stack-sm">
          ${state.reports.length ? state.reports.map((r) => `
            <button class="row-between report-item" data-report="${esc(r.key)}">
              <span>${esc(r.name)}</span>
              <span class="pill">${esc(r.object_type)}</span>
            </button>`).join("") : `<div class="empty">No saved reports are available for this tenant.</div>`}
        </div>
      </section>
      <section class="panel span-8">
        <div class="panel-head"><h2>Result</h2><span class="pill">${esc(state.reportResult?.key || "none")}</span></div>
        <div class="panel-body">${reportResultView()}</div>
      </section>
    </div>`;
}

function reportResultView() {
  const result = state.reportResult;
  if (!result) return `<div class="empty">Select a report to run it.</div>`;
  if (Array.isArray(result.groups) && result.groups.length) {
    return `
      <table><thead><tr><th>Group</th><th>Value</th></tr></thead><tbody>
        ${result.groups.map((g) => `<tr><td>${esc(g.key)}</td><td>${esc(reportNumber(g.value))}</td></tr>`).join("")}
      </tbody></table>`;
  }
  return `<div class="metric"><div class="metric-label"><span>${esc(result.name || result.key)}</span></div><div class="metric-value">${esc(reportNumber(result.value))}</div></div><pre>${pretty(result)}</pre>`;
}

function reportNumber(value) {
  return Number.isFinite(Number(value)) ? intFmt(value) : String(value ?? "");
}

function approvalsView() {
  return `
    ${pageHead("Approvals", "Approval-gated workflow transitions waiting for decision.", `<button id="reloadApprovals">Refresh</button>`)}
    <section class="panel">
      <div class="panel-head"><h2>Pending queue</h2><span class="pill">${state.approvals.length} pending</span></div>
      <div class="panel-table">
        ${state.approvals.length ? `
          <table><thead><tr><th>Approval</th><th>Record</th><th>Transition</th><th>Status</th></tr></thead><tbody>
            ${state.approvals.map((a) => `<tr><td class="mono">${esc(a.id)}</td><td class="mono">${esc(a.record_id)}</td><td>${esc(a.transition_key)}</td><td>${statusBadge(a.status)}</td></tr>`).join("")}
          </tbody></table>` : `<div class="empty">No pending approvals right now.</div>`}
      </div>
    </section>`;
}

function agentsView() {
  const readiness = aiReadiness();
  const sourceCount = state.agentAnswer?.sources?.length || 0;
  const actionDisabled = readiness.canRun ? "" : "disabled";
  const agents = availableAgents();
  return `
    ${pageHead("AI agents", "Grounded specialists that read through permission-checked services.", `
      ${agents.map((agent) => `<button data-agent="${esc(agent.key)}" ${actionDisabled}>${esc(agent.label)}</button>`).join("") || `<button data-route="builder">Add module</button>`}
    `)}
    <div class="grid">
      ${aiReadinessCards(readiness)}
      <section class="panel span-5">
        <div class="panel-head"><h2>Agent readiness</h2><span class="status-pill ${readiness.status === "ready" ? "green" : "amber"}">${esc(readiness.status)}</span></div>
        <div class="panel-body stack">
          ${readiness.reasons.length ? `
            <div class="stack-sm">${readiness.reasons.map((reason) => `<div class="requirement-row"><span class="status-dot amber"></span><p>${esc(reason)}</p></div>`).join("")}</div>
          ` : `<div class="requirement-row"><span class="status-dot ${readiness.provider === "not_configured" ? "amber" : "green"}"></span><p>Published metadata and AI-visible fields are available. Run an agent to verify provider connectivity and retrieve governed sources.</p></div>`}
          <div class="agent-button-grid">
            ${agents.map((agent) => `<button data-agent="${esc(agent.key)}" ${actionDisabled}>${esc(agent.action)}</button>`).join("") || `<button data-route="builder">Install a module</button>`}
          </div>
        </div>
      </section>
      <section class="panel span-7">
        <div class="panel-head"><h2>BI question</h2><button id="askBiBtn" ${actionDisabled}>Ask BI</button></div>
        <div class="panel-body stack">
          <textarea id="biQuestion">${esc(defaultBiQuestion())}</textarea>
          <div id="biAnswer">${answerBlock(state.agentAnswer, readiness.canRun ? "Ask a question or run a specialist agent." : readiness.reasons[0])}</div>
        </div>
      </section>
      <section class="panel span-5">
        <div class="panel-head"><h2>Grounding trail</h2><span class="pill">${sourceCount} sources</span></div>
        <div class="panel-body stack-sm">${groundingTrailView()}</div>
      </section>
      <section class="panel span-7">
        <div class="panel-head"><h2>Provider setup</h2><span class="status-pill ${providerStatusClass(readiness.provider)}">${providerStatusLabel(readiness.provider)}</span></div>
        <div class="panel-body">${providerSetupView(readiness)}</div>
      </section>
    </div>`;
}

function aiReadiness() {
  const objectCount = state.objectTypes.length;
  const aiFields = aiVisibleFieldCount();
  const provider = aiProviderStatus();
  const reasons = [];
  if (!objectCount) reasons.push("Publish an object or install a Builder template before running AI. Retrieval has no governed record surface yet.");
  if (objectCount && !aiFields) reasons.push("Mark at least one non-sensitive field as AI visible in Builder or schema metadata.");
  return {
    objectCount,
    aiFields,
    provider,
    citations: state.agentAnswer?.citations?.length || 0,
    canRun: objectCount > 0 && aiFields > 0,
    status: objectCount > 0 && aiFields > 0 ? (provider === "not_configured" ? "needs setup" : "ready") : "blocked",
    reasons
  };
}

function aiVisibleFieldCount() {
  return state.objectTypes.reduce((sum, object) => sum + (object.fields || []).filter((field) => field.ai_visible).length, 0);
}

function aiProviderStatus() {
  if (state.agentAnswer?.kind === "provider_error" || state.agentAnswer?.provider === "unconfigured") return "not_configured";
  if (state.agentAnswer?.provider) return "verified";
  return "not_checked";
}

function providerStatusLabel(status) {
  if (status === "verified") return "verified";
  if (status === "not_configured") return "not configured";
  return "not checked";
}

function providerStatusClass(status) {
  if (status === "verified") return "green";
  if (status === "not_configured") return "red";
  return "neutral";
}

function aiReadinessCards(readiness) {
  const cards = [
    ["Provider", providerStatusLabel(readiness.provider), "Backend provider state", providerStatusClass(readiness.provider)],
    ["Object types", readiness.objectCount, "Published governed schemas", readiness.objectCount ? "green" : "amber"],
    ["AI-visible fields", readiness.aiFields, "Fields allowed for retrieval", readiness.aiFields ? "green" : "amber"],
    ["Citations", readiness.citations, "Returned by the last answer", readiness.citations ? "green" : "neutral"]
  ];
  return cards.map(([label, value, note, tone]) => `
    <section class="panel span-3 readiness-card">
      <div class="metric-label"><span>${esc(label)}</span><span class="status-pill ${tone}">${esc(String(value))}</span></div>
      <div class="metric-note">${esc(note)}</div>
    </section>`).join("");
}

function groundingTrailView() {
  const answer = state.agentAnswer;
  if (!answer) return `<div class="empty">No AI request has been run in this session.</div>`;
  if (answer.kind === "provider_error") return `<div class="empty error-empty">Provider failed before retrieval, so no governed sources were loaded.</div>`;
  const sources = answer.sources || [];
  if (!sources.length) return `<div class="empty">The last answer returned no source records.</div>`;
  return sources.slice(0, 12).map((s) => `
    <div class="source-card">
      <div class="row-between"><strong>${esc(s.title || s.source_id)}</strong><span class="pill">${esc(s.object_type || "record")}</span></div>
      <p class="mono">${esc(s.source_id || "")}</p>
      <p>${esc(s.snippet || "")}</p>
    </div>`).join("");
}

function providerSetupView(readiness) {
  if (readiness.provider === "verified") {
    return `<div class="requirement-row"><span class="status-dot green"></span><p>Provider connectivity was verified by the last AI response. Answers still read through tenant permissions, record scope, restricted fields, and AI visibility metadata.</p></div>`;
  }
  return `
    <div class="stack">
      <p>AI requests are explicit operator actions. The console will not auto-run agents on navigation or fabricate citations.</p>
      <div class="setup-box">
        <div><span class="mono">LATENTDB_AI_PROVIDER</span><strong>openai-compatible or offline</strong></div>
        <div><span class="mono">LATENTDB_AI_API_KEY</span><strong>required for hosted providers</strong></div>
        <div><span class="mono">LATENTDB_AI_MODEL</span><strong>provider model name</strong></div>
        <div><span class="mono">LATENTDB_AI_BASE_URL</span><strong>optional compatible endpoint</strong></div>
      </div>
      ${readiness.objectCount ? "" : `<button data-route="builder">Open Builder</button>`}
    </div>`;
}

function answerBlock(answer, emptyText) {
  if (!answer) return `<div class="empty">${esc(emptyText)}</div>`;
  if (answer.kind === "provider_error") {
    return `
      <div class="empty error-empty">
        <strong>Provider unavailable</strong>
        <p>${esc(answer.error || answer.text)}</p>
      </div>`;
  }
  return `
    <div class="stack-sm">
      <p>${esc(answer.text).replace(/\n/g, "<br>")}</p>
      <div>${(answer.citations || []).map((id) => `<span class="pill mono">${esc(id)}</span>`).join("")}</div>
      <div class="row muted"><span>${esc(answer.provider)}</span><span>${esc(answer.model)}</span><span>${answer.prompt_tokens || 0} prompt tokens</span></div>
    </div>`;
}

function actionsView() {
  const object = objectByKey() || state.objectTypes[0] || null;
  const payload = JSON.stringify(generatedRecordPayload(object), null, 2);
  const disabled = object ? "" : "disabled";
  return `
    ${pageHead("Action planner", "Dry-run agent mutations before approval-gated execution.", `<button id="dryRunAction" ${disabled}>Dry run</button><button id="executeAction" class="danger" ${disabled}>Execute approved</button>`)}
    <div class="grid">
      <section class="panel span-5">
        <div class="panel-head"><h2>Proposed action</h2><span class="status-pill amber">approval required</span></div>
        <div class="panel-body stack">
          <div class="form-grid" style="grid-template-columns:1fr 1fr">
            <div><label>Operation</label><select id="actionOp"><option value="create_record">Create record</option><option value="update_record">Update record</option></select></div>
            <div><label>Object type</label><select id="actionObject" ${disabled}>${state.objectTypes.map((item) => `<option value="${esc(item.key)}" ${item.key === object?.key ? "selected" : ""}>${esc(objectLabel(item))}</option>`).join("")}</select></div>
          </div>
          <div><label>Record id for updates</label><input id="actionRecord" placeholder="record id"></div>
          <div><label>Payload</label><textarea id="actionPayload" class="mono">${esc(payload)}</textarea></div>
        </div>
      </section>
      <section class="panel span-7">
        <div class="panel-head"><h2>Plan result</h2></div>
        <div class="panel-body"><div id="actionResult" class="empty">${object ? "Run dry-run to inspect exact before and after state." : "Publish an object before planning a record action."}</div></div>
      </section>
    </div>`;
}

function builderView() {
  const def = state.builderDefinition || defaultBuilderDefinition();
  const status = state.builderPublished ? "published" : state.builderValidation?.valid ? "validated" : "draft";
  return `
    ${pageHead("Builder", "Build tenant-specific business objects with schema, permissions, workflow, audit, and AI visibility enforced by the kernel.", `
      <button id="builderSave">Save draft</button>
      <button id="builderValidate">Validate</button>
      <button id="builderPublish" class="primary">Publish</button>
    `)}
    <div class="grid">
      <section class="panel span-7">
        <div class="panel-head"><h2>Governed object definition</h2><span class="status-pill ${statusClass(status)}">${status}</span></div>
        <div class="panel-body stack">
          <div class="row">
            ${["Create Object", "Add Fields", "Define Relations", "Set Permissions", "Configure Workflow", "AI Visibility", "Approval Rules", "Review & Publish"].map((s, i) => `<span class="pill">${i + 1}. ${esc(s)}</span>`).join("")}
          </div>
          <div class="form-grid" style="grid-template-columns:1fr 1fr">
            <div><label>Object key</label><input id="builderKey" value="${esc(def.key)}" placeholder="object_key"></div>
            <div><label>Display name</label><input id="builderLabel" value="${esc(def.label)}" placeholder="Object name"></div>
            <div><label>Module/category</label><input id="builderModule" value="${esc(def.module || "")}" placeholder="custom"></div>
            <div><label>Display field</label><input id="builderDisplay" value="${esc(def.display_field || "")}" placeholder="${esc(def.fields?.[0]?.key || "name")}"></div>
          </div>
          <div><label>Description</label><textarea id="builderDescription">${esc(def.description || "")}</textarea></div>
          <div class="panel">
            <div class="panel-head"><h2>Fields</h2><button id="builderAddField">Add field</button></div>
            <div class="panel-table">${builderFieldTable(def)}</div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Workflow</h2><span class="pill">optional</span></div>
            <div class="panel-body stack-sm">
              <label><input id="builderWorkflowEnabled" type="checkbox" ${def.workflow ? "checked" : ""} style="width:auto;min-height:auto"> Enable simple approval workflow</label>
              <p>Workflow states are generated from this object key and published through the same kernel metadata path.</p>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><h2>Templates</h2><span class="pill">normal metadata</span></div>
            <div class="panel-body stack-sm">
              <p>Templates are only starting points. Every installed module becomes normal governed metadata.</p>
              <div class="row">
                ${(state.builderTemplates || []).map((t) => `<button class="template-install" data-template="${esc(t.key)}">Install ${esc(t.name)}</button>`).join("") || `<span class="muted">No templates loaded.</span>`}
              </div>
            </div>
          </div>
        </div>
      </section>
      <section class="panel span-5">
        <div class="panel-head"><h2>Live preview</h2><span class="pill">${(def.fields || []).length} fields</span></div>
        <div class="panel-body stack">
          <p>AI can search dynamic records, but it can only read fields allowed by tenant permissions and AI visibility rules.</p>
          ${builderIssues()}
          <pre>${pretty(def)}</pre>
          ${state.builderPublished ? `<div class="status-pill green">Published ${esc(state.builderPublished.object_type.key)}</div>` : ""}
        </div>
      </section>
    </div>`;
}

function builderFieldTable(def) {
  const fields = def.fields || [];
  if (!fields.length) return `<div class="empty">Add at least one field. Field keys must be stable snake_case identifiers.</div>`;
  return `
    <table><thead><tr><th>Key</th><th>Label</th><th>Type</th><th>Governance</th></tr></thead><tbody>
      ${fields.map((f, i) => `
        <tr>
          <td><input class="builder-field" data-idx="${i}" data-prop="key" value="${esc(f.key)}"></td>
          <td><input class="builder-field" data-idx="${i}" data-prop="label" value="${esc(f.label)}"></td>
          <td>
            <select class="builder-field" data-idx="${i}" data-prop="type">
              ${["text", "long_text", "number", "money", "date", "date_time", "boolean", "enum", "record_ref", "user_ref"].map((t) => `<option value="${t}" ${f.type === t ? "selected" : ""}>${t}</option>`).join("")}
            </select>
          </td>
          <td class="stack-sm">
            <label><input class="builder-field-check" data-idx="${i}" data-prop="required" type="checkbox" ${f.required ? "checked" : ""} style="width:auto;min-height:auto"> Required</label>
            <label><input class="builder-field-check" data-idx="${i}" data-prop="restricted" type="checkbox" ${f.restricted ? "checked" : ""} style="width:auto;min-height:auto"> Sensitive</label>
            <label><input class="builder-field-check" data-idx="${i}" data-prop="ai_visible" type="checkbox" ${f.ai_visible ? "checked" : ""} style="width:auto;min-height:auto"> AI visible</label>
          </td>
        </tr>`).join("")}
    </tbody></table>`;
}

function builderIssues() {
  const issues = state.builderValidation?.issues || [];
  if (!issues.length) return `<div class="status-pill green">No validation errors loaded</div>`;
  return `<div class="stack-sm">${issues.map((i) => `<div class="status-pill red">${esc(i.path)}: ${esc(i.message)}</div>`).join("")}</div>`;
}

function schemaView() {
  const grouped = groupBy(state.objectTypes, (o) => o.module || "custom");
  return `
    ${pageHead("Schema", "Business modules expressed as metadata.", "")}
    <div class="grid">
      <section class="panel span-4">
        <div class="panel-head"><h2>Object types</h2><span class="pill">${state.objectTypes.length}</span></div>
        <div class="panel-body stack">
          ${Object.entries(grouped).map(([module, items]) => `
            <div class="stack-sm">
              <h3>${esc(module)}</h3>
              ${items.map((o) => `<button class="row-between schema-object" data-object="${esc(o.key)}"><span>${esc(o.label)}</span><span class="pill">${o.fields?.length || 0} fields</span></button>`).join("")}
            </div>`).join("")}
        </div>
      </section>
      <section class="panel span-8">
        <div class="panel-head"><h2>${esc(state.selectedObject?.label || "Object")}</h2><span class="pill">${esc(state.selectedObject?.key || "")}</span></div>
        <div class="panel-table">${schemaTable(state.selectedObject)}</div>
      </section>
    </div>`;
}

function schemaTable(object) {
  if (!object) return `<div class="empty">Select an object type.</div>`;
  return `
    <table><thead><tr><th>Field</th><th>Type</th><th>Required</th><th>Details</th></tr></thead><tbody>
      ${(object.fields || []).map((f) => `
        <tr>
          <td><strong>${esc(f.label)}</strong><div class="mono muted">${esc(f.key)}</div></td>
          <td>${esc(f.type || f.field_type)}</td>
          <td>${f.required ? statusBadge("required") : `<span class="muted">optional</span>`}</td>
          <td>${f.restricted ? `<span class="status-pill amber">restricted</span>` : ""} ${f.ref_object_type ? `<span class="pill">ref ${esc(f.ref_object_type)}</span>` : ""}</td>
        </tr>`).join("")}
    </tbody></table>`;
}

function systemView() {
  return `
    ${pageHead("System", "Runtime status and session context.", `<button id="systemRefresh">Refresh</button><button id="logoutInline">Logout</button>`)}
    <div class="grid">
      <section class="panel span-6">
        <div class="panel-head"><h2>Acceleration backends</h2><span class="pill">${state.accel?.backends?.length || 0}</span></div>
        <div class="panel-body stack-sm">
          ${(state.accel?.backends || []).map((b) => `
            <div class="row-between">
              <span>${esc(b.backend)}</span>
              <span class="status-pill ${b.available ? "green" : "neutral"}">${b.available ? "available" : "fallback"}</span>
            </div>`).join("") || `<div class="empty">Status not loaded.</div>`}
        </div>
      </section>
      <section class="panel span-6">
        <div class="panel-head"><h2>Session</h2></div>
        <div class="panel-body"><pre>${pretty(state.me)}</pre></div>
      </section>
    </div>`;
}

function inspectorView() {
  if (state.selectedRecord) {
    const object = state.objectTypes.find((o) => o.key === state.selectedRecord.object_type);
    return `
      <div class="stack">
        <div>
          <h2>${esc(recordTitle(object, state.selectedRecord))}</h2>
          <p class="mono">${esc(state.selectedRecord.id)}</p>
        </div>
        <div class="row">${statusBadge(state.selectedRecord.workflow_state || state.selectedRecord.data?.status || state.selectedRecord.data?.stage)}</div>
        <pre>${pretty(state.selectedRecord)}</pre>
      </div>`;
  }
  return `
    <div class="stack">
      <div><h2>Workspace context</h2><p>Tenant workspace with metadata modules, records, reports, approvals, and grounded AI.</p></div>
      <div class="stack-sm">
        <div class="row-between"><span>Tenant</span><span class="mono muted">${esc(state.me?.tenant_id?.slice(0, 12))}</span></div>
        <div class="row-between"><span>Role</span><span class="pill">${esc(state.me?.role_keys?.[0])}</span></div>
        <div class="row-between"><span>API</span><span class="status-pill ${state.apiReady ? "green" : "red"}">${state.apiReady ? "ready" : "offline"}</span></div>
      </div>
      <div class="empty">Select a record to inspect its full JSON payload.</div>
    </div>`;
}

function drawerView() {
  return `
    <div class="drawer">
      <div class="drawer-head"><h2>${esc(state.drawer.title)}</h2><button id="closeDrawer">Close</button></div>
      <div class="drawer-body">${state.drawer.body}</div>
    </div>`;
}

function attachRouteEvents() {
  document.querySelectorAll("[data-route]").forEach((el) => {
    el.addEventListener("click", async () => {
      if (el.dataset.object) {
        state.currentObject = el.dataset.object;
        localStorage.setItem("latentdb_object", state.currentObject);
      }
      navigate(el.dataset.route);
    });
  });
  document.querySelector("#refreshBtn")?.addEventListener("click", refreshAll);
  document.querySelector("#logoutBtn")?.addEventListener("click", logout);
  document.querySelector("#globalSearchBtn")?.addEventListener("click", () => {
    state.currentSearch = document.querySelector("#globalSearch")?.value || "";
    navigate("records");
  });
  document.querySelector("#globalSearch")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.querySelector("#globalSearchBtn")?.click();
  });
  document.querySelector("#overviewRefresh")?.addEventListener("click", refreshAll);
  document.querySelector("#primaryAgentRefresh")?.addEventListener("click", async () => {
    const agent = primaryAgent();
    if (agent) await runAgent(agent.key);
    render();
  });
  document.querySelector("#objectSelect")?.addEventListener("change", async (e) => {
    state.currentObject = e.target.value;
    localStorage.setItem("latentdb_object", state.currentObject);
    state.selectedRecord = null;
    await loadRecords();
    render();
  });
  document.querySelector("#recordSearchBtn")?.addEventListener("click", async () => {
    state.currentSearch = document.querySelector("#recordSearch")?.value || "";
    await loadRecords();
    render();
  });
  document.querySelector("#recordSearch")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.querySelector("#recordSearchBtn")?.click();
  });
  document.querySelector("#reloadRecords")?.addEventListener("click", async () => { await loadRecords(); render(); });
  document.querySelector("#openCreateDrawer")?.addEventListener("click", openCreateDrawer);
  document.querySelectorAll("[data-record-id]").forEach((row) => row.addEventListener("click", () => selectRecord(row.dataset.recordId)));
  document.querySelectorAll(".report-item").forEach((el) => el.addEventListener("click", async () => { await loadReport(el.dataset.report); render(); }));
  document.querySelector("#runSelectedReport")?.addEventListener("click", async () => { await loadReport(state.reportResult?.key || state.reports[0]?.key); render(); });
  document.querySelector("#reloadApprovals")?.addEventListener("click", async () => { await loadApprovals(); render(); });
  document.querySelectorAll("[data-agent]").forEach((el) => el.addEventListener("click", async () => { await runAgent(el.dataset.agent); render(); }));
  document.querySelector("#askBiBtn")?.addEventListener("click", askBi);
  document.querySelector("#dryRunAction")?.addEventListener("click", dryRunAction);
  document.querySelector("#executeAction")?.addEventListener("click", executeAction);
  document.querySelector("#actionObject")?.addEventListener("change", (e) => {
    state.currentObject = e.target.value;
    localStorage.setItem("latentdb_object", state.currentObject);
    const object = objectByKey();
    const payload = document.querySelector("#actionPayload");
    if (payload) payload.value = JSON.stringify(generatedRecordPayload(object), null, 2);
  });
  document.querySelector("#builderSave")?.addEventListener("click", saveBuilderDraft);
  document.querySelector("#builderValidate")?.addEventListener("click", validateBuilderDraft);
  document.querySelector("#builderPublish")?.addEventListener("click", publishBuilderDraft);
  document.querySelector("#builderAddField")?.addEventListener("click", () => {
    state.builderDefinition = collectBuilderDefinition();
    state.builderDefinition.fields.push({ key: "new_field", label: "New Field", type: "text", required: false, restricted: false, ai_visible: true });
    render();
  });
  document.querySelectorAll(".builder-field").forEach((el) => el.addEventListener("input", () => {
    state.builderDefinition = collectBuilderDefinition();
  }));
  document.querySelectorAll(".builder-field-check").forEach((el) => el.addEventListener("change", () => {
    state.builderDefinition = collectBuilderDefinition();
    render();
  }));
  document.querySelectorAll(".template-install").forEach((el) => el.addEventListener("click", async () => {
    await installBuilderTemplate(el.dataset.template);
    render();
  }));
  document.querySelectorAll(".schema-object").forEach((el) => el.addEventListener("click", () => {
    state.selectedObject = state.objectTypes.find((o) => o.key === el.dataset.object);
    state.currentObject = el.dataset.object;
    render();
  }));
  document.querySelector("#systemRefresh")?.addEventListener("click", async () => { await loadSystem(); render(); });
  document.querySelector("#logoutInline")?.addEventListener("click", logout);
  document.querySelector("#closeDrawer")?.addEventListener("click", () => { state.drawer = null; render(); });
  document.querySelector("#recordCreateForm")?.addEventListener("submit", createRecordFromForm);
}

async function refreshAll() {
  await checkApi();
  await loadBase();
  await hydrateRoute();
  render();
}

async function loadOverviewData() {
  await loadApprovals();
}

async function loadRecords() {
  if (!state.objectTypes.length) {
    state.recordPage = { items: [], total: 0, limit: 50, offset: 0 };
    state.selectedObject = null;
    return;
  }
  if (!state.objectTypes.some((o) => o.key === state.currentObject)) {
    state.currentObject = state.objectTypes[0].key;
  }
  const query = state.currentSearch ? `?search=${encodeURIComponent(state.currentSearch)}` : "";
  state.recordPage = await api(`/v1/object-types/${state.currentObject}/records${query}`);
  state.selectedObject = state.objectTypes.find((o) => o.key === state.currentObject) || null;
}

function selectRecord(id) {
  state.selectedRecord = state.recordPage?.items?.find((r) => r.id === id) || null;
  render();
}

async function loadReport(key) {
  if (!key) return;
  state.reportResult = await api(`/v1/reports/${key}/run`);
  state.reportResult.key = key;
}

async function loadApprovals() {
  state.approvals = await api("/v1/approvals");
}

async function loadBuilder() {
  const [drafts, templates] = await Promise.all([
    api("/v1/builder/drafts"),
    api("/v1/builder/templates")
  ]);
  state.builderDrafts = drafts;
  state.builderTemplates = templates;
  state.builderDefinition ||= drafts[0]?.definition || definitionFromTemplate(templates[0]) || defaultBuilderDefinition();
}

function definitionFromTemplate(template) {
  if (!template?.objects?.length) return null;
  return structuredClone(template.objects[0]);
}

function defaultBuilderDefinition() {
  return {
    key: "custom_object",
    label: "Custom Object",
    label_plural: "Custom Objects",
    description: "Tenant-specific object governed by schema, permissions, workflow, audit, and AI visibility.",
    icon: "CO",
    module: "custom",
    display_field: "name",
    fields: [
      { key: "name", label: "Name", type: "text", required: true, display: true, ai_visible: true },
      { key: "status", label: "Status", type: "enum", enum_options: ["new", "active", "closed"], ai_visible: true },
      { key: "internal_note", label: "Internal Note", type: "long_text", restricted: true, ai_visible: false }
    ],
    relations: [],
    workflow: null,
    permissions: [],
    approval_rules: [],
    sensitive_ai_visibility_confirmed: false
  };
}

function simpleBuilderWorkflow(objectType) {
  return {
    key: `${objectType}_approval`,
    object_type: objectType,
    name: `${objectType.replaceAll("_", " ")} Approval`,
    initial_state: "draft",
    states: [
      { key: "draft", label: "Draft", terminal: false },
      { key: "review", label: "Review", terminal: false },
      { key: "approved", label: "Approved", terminal: false },
      { key: "closed", label: "Closed", terminal: true },
      { key: "cancelled", label: "Cancelled", terminal: true }
    ],
    transitions: [
      { key: "submit", from: "draft", to: "review", label: "Submit", requires_approval: false },
      { key: "approve", from: "review", to: "approved", label: "Approve", requires_approval: true, approval_policy: "default" },
      { key: "close", from: "approved", to: "closed", label: "Close", requires_approval: false },
      { key: "cancel", from: "draft", to: "cancelled", label: "Cancel", requires_approval: false }
    ]
  };
}

function collectBuilderDefinition() {
  const current = state.builderDefinition || defaultBuilderDefinition();
  const key = document.querySelector("#builderKey")?.value || current.key;
  const fields = Array.from(document.querySelectorAll(".builder-field[data-prop='key']")).map((input) => {
    const idx = input.dataset.idx;
    const existing = current.fields?.[idx] || {};
    const get = (prop) => document.querySelector(`.builder-field[data-idx="${idx}"][data-prop="${prop}"]`)?.value;
    const checked = (prop) => document.querySelector(`.builder-field-check[data-idx="${idx}"][data-prop="${prop}"]`)?.checked || false;
    const type = get("type") || existing.type || "text";
    const field = {
      ...existing,
      key: get("key") || existing.key,
      label: get("label") || existing.label,
      type,
      required: checked("required"),
      restricted: checked("restricted"),
      ai_visible: checked("ai_visible")
    };
    if (type === "enum" && !field.enum_options?.length) field.enum_options = ["draft", "active", "closed"];
    if (type === "record_ref" && !field.ref_object_type) field.ref_object_type = state.objectTypes[0]?.key || key;
    return field;
  });
  const workflowEnabled = document.querySelector("#builderWorkflowEnabled")?.checked;
  return {
    ...current,
    key,
    label: document.querySelector("#builderLabel")?.value || current.label,
    label_plural: `${document.querySelector("#builderLabel")?.value || current.label}s`,
    description: document.querySelector("#builderDescription")?.value || "",
    module: document.querySelector("#builderModule")?.value || undefined,
    display_field: document.querySelector("#builderDisplay")?.value || undefined,
    fields,
    workflow: workflowEnabled ? simpleBuilderWorkflow(key) : null
  };
}

async function saveBuilderDraft() {
  state.builderDefinition = collectBuilderDefinition();
  const draft = await api("/v1/builder/drafts", { method: "POST", body: JSON.stringify({ definition: state.builderDefinition }) });
  state.builderDrafts = await api("/v1/builder/drafts");
  state.builderValidation = await api(`/v1/builder/drafts/${draft.id}/validate`, { method: "POST", body: "{}" });
  render();
}

async function validateBuilderDraft() {
  await saveBuilderDraft();
}

async function publishBuilderDraft() {
  state.builderDefinition = collectBuilderDefinition();
  const draft = await api("/v1/builder/drafts", { method: "POST", body: JSON.stringify({ definition: state.builderDefinition }) });
  state.builderValidation = await api(`/v1/builder/drafts/${draft.id}/validate`, { method: "POST", body: "{}" });
  if (!state.builderValidation.valid) {
    render();
    return;
  }
  state.builderPublished = await api(`/v1/builder/drafts/${draft.id}/publish`, { method: "POST", body: JSON.stringify({ id: draft.id }) });
  await loadBase();
  state.currentObject = state.builderPublished.object_type.key;
  localStorage.setItem("latentdb_object", state.currentObject);
  navigate("records");
}

async function installBuilderTemplate(key) {
  const result = await api("/v1/builder/templates/install", {
    method: "POST",
    body: JSON.stringify({ key, include_sample_records: true })
  });
  state.builderPublished = { object_type: result.object_types?.[0] || { key } };
  await loadBase();
  state.currentObject = result.object_types?.[0]?.key || state.currentObject;
  localStorage.setItem("latentdb_object", state.currentObject);
  await loadBuilder();
}

async function runAgent(kind) {
  const readiness = aiReadiness();
  if (!readiness.canRun) {
    state.agentAnswer = {
      kind: "readiness_blocked",
      text: readiness.reasons.join("\n"),
      citations: [],
      sources: [],
      provider: providerStatusLabel(readiness.provider),
      model: "none",
      prompt_tokens: 0
    };
    return;
  }
  const agent = aiCapabilities().agents.find((item) => item.key === kind) || primaryAgent();
  if (!agent) {
    state.agentAnswer = {
      kind: "readiness_blocked",
      text: "No built-in agent matches the currently published modules.",
      citations: [],
      sources: [],
      provider: providerStatusLabel(readiness.provider),
      model: "none",
      prompt_tokens: 0
    };
    return;
  }
  try {
    state.agentAnswer = await api(agent.endpoint, { method: "POST", body: "{}" });
  } catch (err) {
    state.agentAnswer = {
      kind: "provider_error",
      text: err.message,
      error: err.message,
      citations: [],
      sources: [],
      provider: "unconfigured",
      model: "none",
      prompt_tokens: 0
    };
  }
}

async function askBi() {
  const question = document.querySelector("#biQuestion")?.value || defaultBiQuestion();
  const readiness = aiReadiness();
  if (!readiness.canRun) {
    state.agentAnswer = {
      kind: "readiness_blocked",
      text: readiness.reasons.join("\n"),
      citations: [],
      sources: [],
      provider: providerStatusLabel(readiness.provider),
      model: "none",
      prompt_tokens: 0
    };
    render();
    return;
  }
  try {
    state.agentAnswer = await api(aiCapabilities().bi_ask.endpoint, { method: "POST", body: JSON.stringify({ question }) });
  } catch (err) {
    state.agentAnswer = {
      kind: "provider_error",
      text: err.message,
      error: err.message,
      citations: [],
      sources: [],
      provider: "unconfigured",
      model: "none",
      prompt_tokens: 0
    };
  }
  render();
}

async function loadSystem() {
  state.accel = await api("/v1/accel/status");
}

function openCreateDrawer() {
  const object = state.selectedObject || state.objectTypes.find((o) => o.key === state.currentObject);
  if (!object) {
    state.drawer = {
      title: "Create record",
      body: `<div class="empty">Publish an object or install a Builder template before creating records.</div>`
    };
    render();
    return;
  }
  state.drawer = {
    title: `Create ${object.label || state.currentObject}`,
    body: `
      <form id="recordCreateForm" class="stack">
        <p>Generated from the published schema. Required fields are enforced by the kernel.</p>
        ${(object.fields || []).filter((f) => !f.restricted).map((f) => recordInput(f)).join("")}
        <button class="primary" type="submit">Create ${esc(object.label || "record")}</button>
        <div id="recordCreateResult"></div>
      </form>`
  };
  render();
}

function recordInput(field) {
  const type = String(field.type || field.field_type || "text");
  const required = field.required ? "required" : "";
  if (type === "enum") {
    return `<div><label>${esc(field.label)}${field.required ? " *" : ""}</label><select name="${esc(field.key)}" ${required}>${(field.enum_options || []).map((o) => `<option value="${esc(o)}">${esc(o)}</option>`).join("")}</select></div>`;
  }
  if (type === "boolean") {
    return `<label><input name="${esc(field.key)}" type="checkbox" style="width:auto;min-height:auto"> ${esc(field.label)}</label>`;
  }
  const htmlType = type === "money" || type === "number" ? "number" : type === "date" ? "date" : type === "date_time" ? "datetime-local" : "text";
  return `<div><label>${esc(field.label)}${field.required ? " *" : ""}</label><input name="${esc(field.key)}" type="${htmlType}" ${required}></div>`;
}

function sampleValue(field) {
  const kind = String(field.field_type || field.type || "").toLowerCase();
  if (field.enum_options?.length) return field.enum_options[0];
  if (kind.includes("money") || kind.includes("number")) return 0;
  if (kind.includes("date")) return new Date().toISOString().slice(0, kind.includes("time") ? 16 : 10);
  if (kind.includes("boolean")) return false;
  if (kind.includes("json")) return {};
  return `${field.label || field.key}`;
}

async function createRecordFromForm(event) {
  event.preventDefault();
  const object = state.selectedObject || state.objectTypes.find((o) => o.key === state.currentObject);
  const form = new FormData(event.target);
  const data = {};
  for (const field of object?.fields || []) {
    if (field.restricted) continue;
    const type = String(field.type || field.field_type || "text");
    if (type === "boolean") {
      data[field.key] = form.get(field.key) === "on";
      continue;
    }
    const raw = form.get(field.key);
    if (raw === null || raw === "") continue;
    if (type === "money" || type === "number") {
      data[field.key] = Number(raw);
    } else {
      data[field.key] = raw;
    }
  }
  const target = document.querySelector("#recordCreateResult");
  try {
    const rec = await api(`/v1/object-types/${state.currentObject}/records`, {
      method: "POST",
      body: JSON.stringify({ data })
    });
    target.innerHTML = `<div class="status-pill green">Created ${esc(rec.id)}</div>`;
    await loadRecords();
  } catch (err) {
    target.innerHTML = `<div class="status-pill red">${esc(err.message)}</div>`;
  }
}

function actionFromForm() {
  const op = document.querySelector("#actionOp")?.value || "create_record";
  const objectType = document.querySelector("#actionObject")?.value || state.currentObject || defaultObjectKey();
  if (!objectType) throw new Error("No object type is available for action planning");
  const recordId = document.querySelector("#actionRecord")?.value || null;
  const payload = JSON.parse(document.querySelector("#actionPayload")?.value || "{}");
  return {
    kind: "operator_console",
    description: `${op.replace("_", " ")} from UI console`,
    op,
    object_type: objectType,
    record_id: recordId || undefined,
    payload,
    safety_level: 3,
    risk_score: 0.35
  };
}

async function dryRunAction() {
  const target = document.querySelector("#actionResult");
  try {
    const plan = await api(aiActionEndpoint("dry_run") || "/v1/ai/actions/dry-run", { method: "POST", body: JSON.stringify(actionFromForm()) });
    target.innerHTML = `<pre>${pretty(plan)}</pre>`;
  } catch (err) {
    target.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
}

async function executeAction() {
  const target = document.querySelector("#actionResult");
  try {
    const action = actionFromForm();
    const result = await api(aiActionEndpoint("execute") || "/v1/ai/actions/execute", { method: "POST", body: JSON.stringify({ action, approved: true }) });
    target.innerHTML = `<pre>${pretty(result)}</pre>`;
    await loadRecords();
  } catch (err) {
    target.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
}

function groupBy(items, keyFn) {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    acc[key] ||= [];
    acc[key].push(item);
    return acc;
  }, {});
}

boot();
