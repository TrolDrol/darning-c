import {createStudio} from "/studio.js";
import {createAccountEditor} from "/account.js";
import {createPageGuide} from "/page_guide.js";
import {githubFields, mountGithub, githubSelection, boundSourceOptions, archiveBase64, projectUpload} from "/source_picker.js";
import {createJournal} from "/journal.js";
import {createPortal} from "/portal.js";
import {setProjectChoices} from "/project_hub.js";
import {createProjectScreens} from "/project.js";
import {createRelease, gateResult} from "/release.js";

const page = document.querySelector("#page");
const dialog = document.querySelector("#run-dialog");
const main = document.querySelector("#main");
const workspaceViews = ["runs", "outbox", "studio"];
const portalViews = ["analytics", "projects", "news"];
const projectViews = ["issues", "release", "repository"];
const navigation = document.querySelector("#navigation");
const controls = document.querySelector("#workspace-controls");
const shareProject = document.querySelector("#share-project");
const signOut = document.querySelector("#sign-out");
const status = {
  queued: ["В очереди", "neutral"],
  running: ["Идёт проверка", "amber"],
  review: ["Требует внимания", "amber"],
  passed: ["Проверка пройдена", ""],
  skipped: ["Без анализа содержимого", "neutral"],
  partial: ["Проверено частично", "red"],
  failed: ["Проверка не завершилась", "red"]
};
const deliveryStatus = {
  simulated: ["В локальной очереди", "neutral"],
  queued: ["Ожидает отправки", "neutral"],
  sending: ["Приём ещё не подтверждён", "amber"],
  sent: ["Принято SMTP-сервером", ""],
  temporary: ["Временный сбой", "amber"],
  failed: ["Ошибка отправки", "red"],
  unknown: ["Результат неизвестен", "amber"],
  superseded: ["Снимок изменился", "neutral"]
};
const triageLabels = {open: "На рассмотрении", accepted: "Риск принят", false_positive: "Ложное срабатывание"};
const noveltyLabels = {new: "Новое", known: "Уже известно", unknown: "Новизна неизвестна"};
const stages = {done: ["✓", ""], error: ["!", "red"], pending: ["…", "amber"], skipped: ["−", "neutral"]};
const deliveryStage = {simulated: "done", queued: "pending", sending: "pending", sent: "done",
  temporary: "error", failed: "error", unknown: "error", superseded: "skipped"};
const dateFormat = new Intl.DateTimeFormat("ru", {dateStyle: "short", timeStyle: "short"});
let workspace;
let toastTimeout;
let dialogContext;
let requestInFlight = false;
let savedDraft;
let selectedRun;
let detailError;
let detailMarker;
let renderedPage;
let mutation = 0;
let detailRead = 0;
let pollInFlight = false;
let mode;
let viewer;
let policyVersion;
let projectId;
let projects = [];
let authRevision = 0;
let loginForInvite = false;
let portalView;

const portal = createPortal({page, request, announce, getProjectId: () => projectId, getViewer: () => viewer, download});

const escape = value => String(value ?? "").replace(/[&<>"']/g, char => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char]
));

const chip = (text, tone = "") => `<span class="chip ${tone}">${escape(text)}</span>`;
const dateLabel = value => dateFormat.format(new Date(value));
function sameSpec(first, second) {
  return [...new Set([...Object.keys(first), ...Object.keys(second)])].every(key =>
    key === "gateMinimum" ? (first[key] || "off") === (second[key] || "off") :
      JSON.stringify(first[key]) === JSON.stringify(second[key]));
}
const isDirty = () => !sameSpec(workspace.draft, workspace.version.spec);
const needsSave = () => !sameSpec(workspace.draft, savedDraft);
const canWrite = () => workspace.settings.canWrite !== false;
const projectScreens = createProjectScreens({page, request, getProjectId: () => projectId, announce, escape, canWrite});
const release = createRelease({page, request, getProjectId: () => projectId, getWorkspace: () => workspace, download});
const studio = createStudio({page, request, getProjectId: () => projectId || "default", hasRepositorySettings: () => mode === "production",
  getSourcePolicy: () => workspace.sourcePolicy, canWrite, announce, escape});
const journal = createJournal({page, request, getProjectId: () => projectId || "default", getSettings: () => workspace?.settings || {}, escape, announce});
const menu = document.querySelector("#menu-toggle");
const guide = createPageGuide(page, document.querySelector("#page-help"));
const accountTools = document.querySelector(".account-tools");
const accountEditor = createAccountEditor({request, getViewer: () => viewer,
  getProject: () => projects.find(project => project.id === projectId), onSave: updated => {
  viewer = updated;
  accountEditor.refresh();
  announce("Профиль сохранён.");
}});
new ResizeObserver(([entry]) => {
  document.documentElement.style.setProperty("--masthead-measured", Math.ceil(entry.target.getBoundingClientRect().height) + "px");
}).observe(document.querySelector(".masthead"));
document.addEventListener("click", event => {
  if (accountTools.open && (!accountTools.contains(event.target) || event.target.closest("button,a"))) accountTools.open = false;
});
accountTools.addEventListener("keydown", event => {
  if (event.key === "Escape") { accountTools.open = false; accountTools.querySelector("summary").focus(); }
});
function closeMenu() {
  navigation.classList.remove("menu-open");
  menu.setAttribute("aria-expanded", "false");
}
menu.addEventListener("click", () => menu.setAttribute("aria-expanded", String(navigation.classList.toggle("menu-open"))));
navigation.addEventListener("click", closeMenu);
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && navigation.classList.contains("menu-open")) { closeMenu(); menu.focus(); }
});
const asynchronous = () => Boolean(workspace.settings.asynchronous);
const isActive = run => ["queued", "running"].includes(run?.status);
const findingCount = run => run.findingCount ?? run.findings?.length ?? 0;
const diagnosticCount = run => run.diagnosticCount ?? run.diagnostics?.length ?? 0;
const runHref = run => `#runs/${run.id}`;
const runById = id => selectedRun?.id === id ? selectedRun : workspace.runs.find(run => run.id === id);
const prHref = event => {
  const repository = event.repository.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${repository}/pull/${encodeURIComponent(event.prNumber)}`;
};

async function request(url, data, {signal} = {}) {
  const endpoint = new URL(url, location.origin);
  if (mode === "production" && projectId && /^\/api\/(?:workspace|runs(?:\/[a-f0-9]{32})?|draft|publish|triage|delivery\/retry)$/.test(endpoint.pathname)) {
    endpoint.searchParams.set("project", projectId);
  }
  const headers = {"X-Workspace-Session": "1"};
  const options = {headers, signal};
  if (data !== undefined) {
    headers["Content-Type"] = "application/json";
    Object.assign(options, {method: "POST", body: JSON.stringify(data)});
  }
  const response = await fetch(endpoint, options);
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && viewer && endpoint.pathname !== "/api/login") signedOut();
    const fallback = response.status === 429 && endpoint.pathname === "/api/register"
      ? "Слишком много попыток регистрации. Попробуйте через минуту." : "Сервис не ответил.";
    throw Object.assign(new Error(result?.error || fallback), {code:result?.code});
  }
  if (viewer && endpoint.pathname === "/api/projects") {
    if (result.projects) projects = result.projects;
    else if (result.project) projects = [...projects, result.project];
    updateNavigation(currentRoute().view);
  }
  return result;
}

async function download(url) {
  const response = await fetch(url, {headers: {"X-Workspace-Session": "1"}});
  if (!response.ok) {
    if (response.status === 401) signedOut();
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Выгрузка недоступна.");
  }
  const href = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = href;
  link.download = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] || "report";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(href), 1000);
}

function announce(message, error = false) {
  const toast = document.querySelector("#toast");
  toast.className = error ? "error" : "";
  toast.textContent = message;
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.textContent = "";
  }, 4500);
}

const versionLabel = run => run.origin === "automation" ? `Схема ${escape(run.workflow.number)}` :
  run.workflow.preview ? "Предпросмотр" : `v${escape(run.workflow.number)}`;

function runRows(runs) {
  if (!runs.length) return '<p class="empty">История проверок пока пуста.</p>';
  return `<div class="table-wrap">
    <table><thead><tr><th scope="col">Снимок</th><th scope="col">Результат</th><th scope="col">Версия</th><th scope="col">Замечания безопасности</th><th scope="col">Ошибки проверки</th><th scope="col">Время</th></tr></thead>
      <tbody>${runs.map(run => `<tr>
        <td><a class="link-button" href="${runHref(run)}">${escape(run.source)}</a></td>
        <td>${chip(...status[run.status])}</td><td>${versionLabel(run)}</td><td>${isActive(run) || ["failed","skipped"].includes(run.status) ? "—" : findingCount(run)}</td>
        <td>${isActive(run) ? "—" : diagnosticCount(run)}</td><td>${dateLabel(run.createdAt)}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
}

function renderFinding(finding, run, open) {
  const recommendation = finding.recommendation;
  const label = finding.level === "high" ? ["Высокая", "red"] : ["Средняя", "amber"];
  const decision = finding.triageDecision;
  const triage = `<div class="triage-summary"><p><strong>Решение</strong> ${escape(triageLabels[finding.triage])}</p>
    ${decision ? `<p>${escape(decision.reason)}</p><p class="fine-print">${escape(decision.actor)} · ${dateLabel(decision.at)}
      · Пересмотр до <time datetime="${escape(decision.expiresAt)}">${escape(decision.expiresAt)}</time></p>` : ""}
    ${canWrite() ? `<button type="button" class="button" data-action="edit-triage" data-run="${run.id}"
      data-finding="${escape(finding.id)}">Изменить решение</button>` : ""}</div>`;
  return `<details class="finding" data-detail="${escape(finding.id)}" ${open ? "open" : ""}>
    <summary>${chip(...label)}<strong>${escape(finding.title)}</strong>
      <code>${escape([finding.file, finding.line, finding.column].filter(value => value != null).join(":"))}</code></summary>
    <div class="finding-detail">
      ${finding.issueId ? `<a href="#projects/issues/${encodeURIComponent(finding.issueId)}">Карточка и история замечания</a>` : ""}
      <p><strong>Правило</strong> <code>${escape(finding.ruleId)}</code>
        ${finding.novelty ? chip(noveltyLabels[finding.novelty], "neutral") : ""}</p>
      <pre><code>${escape(finding.evidence)}</code></pre>
      ${recommendation ? `${chip(recommendation.origin === "llm" ? "Пояснение ИИ" : "Рекомендация из каталога", "neutral")}
        <p><strong>Риск</strong> ${escape(recommendation.summary)}</p>
        <p><strong>Исправление</strong> ${escape(recommendation.action)}</p>
        <p><strong>Проверка</strong> ${escape(finding.verify)}</p>` : `<p>${escape(finding.risk)}</p>`}
      ${asynchronous() || !canWrite() ? triage : `<label class="field">Решение по замечанию
        <select data-triage="${escape(finding.id)}" data-run="${run.id}">
          ${Object.entries(triageLabels).map(([key, name]) =>
            `<option value="${key}" ${key === finding.triage ? "selected" : ""}>${name}</option>`).join("")}
        </select>
      </label>`}
    </div>
  </details>`;
}

function ruleScope(spec) {
  if (!Array.isArray(spec?.rules)) return "";
  const selected = spec.rules;
  const omitted = Object.keys(workspace.rules).filter(id => !selected.includes(id));
  const describe = ids => ids.map(id => `<li><code>${escape(id)}</code> ${escape(workspace.rules[id]?.title || id)}</li>`).join("");
  return `<details class="coverage"${omitted.length ? " open" : ""}>
    <summary>Правила сценария · ${selected.length}</summary>
    <ul>${describe(selected)}</ul>
    ${omitted.length ? `<p>Вне этой проверки</p><ul>${describe(omitted)}</ul>
      ${canWrite() ? '<a class="link-button" href="#scenarios">Открыть автоматизацию</a>' : ""}` : ""}
  </details>`;
}

function repositoryInventory(run) {
  const inventory = run.inventory;
  if (!inventory) return run.skipReason ? `<p class="coverage">${escape(run.skipReason)}</p>` : "";
  const types = Object.entries(inventory.extensions || {}).sort(([a, n], [b, m]) => m - n || a.localeCompare(b));
  const extension = key => key === "" ? "Без расширения" : key === "(other)" ? "Прочие" : key;
  const checked = new Set((run.coverage || []).filter(item => item.status === "done" && item.engine !== "repository").map(item => item.file));
  return `<section class="coverage inventory"><h3>${inventory.scope === "paths" ? "Состав выбранных файлов" : "Состав снимка"}</h3>
    <p>Файлов в описи · <strong>${escape(inventory.totalFiles)}</strong><br>
      ${Array.isArray(inventory.sensitivePaths) ? `Имен с признаками секретов по правилу REPO-001 · <strong>${inventory.sensitivePaths.length}</strong><br>` : ""}
      Файлов с проверенным содержимым · <strong>${checked.size}</strong></p>
    ${types.length ? `<details${types.length <= 12 ? " open" : ""}><summary>Файлы по расширениям</summary><ul>${types.map(([key, n]) => `<li><code>${escape(extension(key))}</code> · ${escape(n)}</li>`).join("")}</ul></details>` : ""}
    ${run.skipReason ? `<p>${escape(run.skipReason)}</p>` : ""}
  </section>`;
}

function renderRun(run) {
  const stepLabels = {...Object.fromEntries(workspace.steps.map(step => [step.id, step.label])),
    repository:"Имена файлов", python:"Python", config:"JSON", secrets:"Поиск секретов", sast:"Kotlin и Spring", sca:"Зависимости"};
  const active = isActive(run);
  const actionable = canWrite() && !active && !run.event && !["github_trial","automation"].includes(run.origin) && !run.workflow.preview && run.status !== "failed";
  const coverageStatus = {done: "Проверен", error: "Ошибка файла", skipped: "Пропущен"};
  const diagnostics = run.diagnostics || [];
  return `
    <section class="panel result">
      <header class="panel-head"><div><h2>Отчёт проверки</h2>
         <p>Запуск <code class="revision">${escape(run.id)}</code> · Сценарий ${versionLabel(run)}</p>
         <p>Источник · ${escape(run.source)}${run.revision ? ` · Ревизия <code class="revision">${escape(run.revision)}</code>` : ""}</p></div>
        <div class="page-actions">
          ${!active ? reportDownloads(run) : ""}
          ${run.origin === "automation" ? `<a class="button" href="#scenarios/${encodeURIComponent(run.id)}?automationId=${encodeURIComponent(run.automationId || "default")}">Открыть схему запуска</a>` : ""}
          ${actionable ? `<button type="button" class="button" data-action="repeat" data-run="${run.id}">Повторить проверку</button>` : ""}
        </div>
      </header>
      <div class="summary-strip" aria-live="polite">${chip(...status[run.status])}
        ${run.gate ? gateResult(run.gate) : ""}
        ${run.event ? `<a class="link-button" href="${escape(prHref(run.event))}">Pull request #${escape(run.event.prNumber)}</a>` : ""}
        ${run.comparison?.status === "unavailable" ? chip("Базовый снимок частично или полностью недоступен", "neutral") : ""}
        ${run.durationMs != null ? `<span>${(run.durationMs / 1000).toLocaleString("ru", {maximumFractionDigits: 2})} с</span>` : ""}
      </div>
      ${run.stages.length ? `<div class="stages" aria-label="Результаты шагов">${run.stages.map(stage => {
        const delivery = stage.id === "deliver" ? run.delivery : null;
        const [icon, tone] = stages[deliveryStage[delivery?.status] ?? stage.status];
        return `<span title="${escape(delivery?.message || stage.message)}">${chip(`${icon} ${stepLabels[stage.id] ?? stage.id}`, tone)}</span>`;
      }).join("")}</div>` : ""}
      ${diagnostics.length ? `<section class="coverage"><h3>Ошибки проверки (${diagnostics.length})</h3>
        <ul>${diagnostics.map(item => `<li>${item.engine ? escape(stepLabels[item.engine] || item.engine) : ""}
          ${item.file ? `<code>${escape(item.file)}${item.line ? `:${escape(item.line)}${item.column ? `:${escape(item.column)}` : ""}` : ""}</code>` : ""}
          <span>${escape(item.message)}</span></li>`).join("")}</ul>
        ${diagnostics.some(item => item.file) ? "<p>Исправьте ошибки разбора и повторите проверку, чтобы применить правила безопасности к этим файлам.</p>" : ""}</section>` : ""}
      ${repositoryInventory(run)}
      ${run.coverageNote ? `<p class="coverage">${escape(run.coverageNote)}</p>` : ""}
      ${ruleScope(run.workflow?.spec)}
      ${run.coverage?.length ? `<section class="coverage"><h3>Охват проверки</h3><ul>${run.coverage.map(file =>
        `<li><code>${escape(file.file)}</code> ${chip(coverageStatus[file.status], stages[file.status]?.[1])}
          ${file.status === "error" ? "" : `<span>${escape(file.message)}</span>`}</li>`
      ).join("")}</ul></section>` : ""}
      ${run.delivery || run.githubCheck ? `<div class="summary-strip">
        ${run.delivery ? chip(...deliveryBadge(run.delivery, "smtp")) : ""}
        ${run.githubCheck ? chip(...deliveryBadge(run.githubCheck, "github")) : ""}
        <a class="link-button" href="#outbox/${run.id}">Сводка доставки</a></div>` : ""}
      ${active ? '<p class="empty">Отчёт обновится после завершения проверки.</p>' : ""}
      ${run.status === "failed" && !diagnostics.length ? '<p class="empty">Анализ не завершён.</p>' : ""}
      ${run.findings.length ? `<div class="findings">${run.findings.map((finding, index) => renderFinding(finding, run, index === 0)).join("")}</div>`
        : !active && !["failed","skipped"].includes(run.status) ? `<p class="empty">${run.status === "partial" ? "В завершённых шагах замечаний нет." : "В проверенных файлах по выбранным правилам замечаний нет."}</p>` : ""}
      ${run.fixed.length ? `<div class="fixed-list"><strong>Закрыто повторной проверкой</strong>
        <ul>${run.fixed.map(finding => `<li>${escape(finding.ruleId)} · ${escape(finding.title)} · ${escape(finding.file)}</li>`).join("")}</ul></div>` : ""}
    </section>`;
}

function reportDownloads(run) {
  return Object.entries({xlsx: "Excel (.xlsx)", "csv-ru": "CSV", json: "JSON"}).map(([format, label]) => {
    const query = new URLSearchParams({project: run.projectId || projectId || "default", runId: run.id, format});
    return `<a class="button" href="/api/export?${escape(query)}" data-report-download download>${label}</a>`;
  }).join("");
}

function renderRuns(runId) {
  if (runId) {
    const run = runById(runId);
    return `
    <header class="page-heading"><div><h1>Запуск проверки</h1>
      ${run ? `<p>${dateLabel(run.createdAt)} · ${escape(run.workflow.spec.name)}</p>` : ""}</div>
      <div class="page-actions"><a href="#projects/journal/runs" class="link-button">Все запуски</a></div></header>
    ${run?.stages ? renderRun(run) : detailPlaceholder()}`;
  }
  return `
    <header class="page-heading"><div><h1>Запуски</h1><p>Результаты проверок и история опубликованных сценариев.</p></div>
      ${canWrite() ? '<button type="button" class="button primary" data-action="open-run">Запустить проверку</button>' : ""}</header>
    <section class="panel">${runRows(workspace.runs)}</section>`;
}

function detailPlaceholder() {
  const message = asynchronous() ? detailError || "Загружаем отчёт…" : "Запуск не найден в истории.";
  return `<section class="panel"><p class="empty" role="status">${escape(message)}</p></section>`;
}

function deliveryBadge(delivery, channel) {
  return channel === "github" && delivery.status === "sent" ? ["Принято GitHub", ""] : deliveryStatus[delivery.status];
}

function renderDelivery(run, channel) {
  const github = channel === "github";
  const delivery = github ? run.githubCheck : run.delivery;
  const configured = github ? workspace.settings.githubConfigured : workspace.settings.smtpConfigured;
  const retryable = canWrite() && configured && (delivery.status === "temporary" || (!asynchronous() && delivery.status === "queued"));
  return `<article class="mail"><div class="mail-heading"><strong>${github ? "GitHub Checks" : escape(delivery.recipient)}</strong>
      ${chip(...deliveryBadge(delivery, channel))}</div>
    <p>${escape(run.source)} · v${run.workflow.number} · ${dateLabel(run.createdAt)}</p>
    ${delivery.channel === "smtp" ? `<p>SMTP${delivery.address ? ` · ${escape(delivery.address)}` : ""} · Попыток ${delivery.attempts}</p>` : ""}
    ${delivery.message ? `<p>${escape(delivery.message)}</p>` : ""}
    ${!run.findings && delivery.findingIds?.length ? `<p>Рекомендаций ${delivery.findingIds.length}</p>` : ""}
    ${(run.findings || []).filter(finding => delivery.findingIds?.includes(finding.id)).map(finding =>
      `<p><strong>${escape(finding.title)}</strong> ${escape(finding.recommendation?.action || finding.fix)}</p>`
    ).join("")}
    <div class="mail-actions"><a class="link-button" href="${runHref(run)}">Открыть отчёт</a>
      ${github && run.event ? `<a class="link-button" href="${escape(prHref(run.event))}">Открыть pull request</a>` : ""}
      ${retryable ? `<button type="button" class="button" data-action="retry-delivery" data-run="${run.id}" data-channel="${channel}">
        ${delivery.status === "queued" ? "Отправить" : "Повторить отправку"}</button>` : ""}</div>
  </article>`;
}

function renderOutbox(runId) {
  const run = runId ? runById(runId) : null;
  const cards = (runId ? (run ? [run] : []) : workspace.runs).flatMap(item => [
    item.delivery ? renderDelivery(item, "smtp") : "",
    item.githubCheck ? renderDelivery(item, "github") : ""
  ]).filter(Boolean);
  return `<header class="page-heading"><div><h1>Доставка</h1><p>Сводки рекомендаций и результаты отправки.</p></div>
    ${runId ? '<a class="link-button" href="#projects/journal/delivery">Все сводки</a>' : ""}</header>
    ${runId && !run?.stages ? detailPlaceholder() : `
    <section class="panel"><header class="panel-head"><h2>Исходящие</h2></header>
      ${cards.length ? `<div class="outbox">${cards.join("")}</div>`
        : '<p class="empty">Сводок пока нет.</p>'}
    </section>`}`;
}

function currentRoute() {
  const hash = location.hash.slice(1);
  const [, head, tail] = /^([^/?]*)(.*)$/.exec(hash);
  let route = head;
  let detail = tail.replace(/^\//, "");
  if (mode === "production") {
    if (route === "invite" && !loginForInvite) return {view: route, detail};
    if (!viewer) return {view: route === "register" ? "register" : "login"};
  }
  if (["scenarios", "workflow", "automation"].includes(route)) {
    route = "studio";
    detail = detail.replace(/^(?:automation|rules)(?:\/|(?=\?|$))/, "");
  }
  if (route === "projects" && detail) {
    const [, section, rest] = /^([^/?]+)(.*)$/.exec(detail) || [];
    const child = {journal:"journal", repositories:"repository", issues:"issues", releases:"release", analytics:"analytics"}[section];
    if (child) {
      route = child;
      detail = rest.replace(/^\//, "");
    }
  }
  if (route === "profile") { route = "issues"; detail = "mine?scope=all"; }
  if (route === "logs" || (!detail && ["runs","outbox"].includes(route))) {
    detail = {runs:"runs", outbox:"delivery", logs:"audit"}[route];
    route = "journal";
  }
  if (mode === "production") {
    if (route === "analytics" && !projectId) return {view:"projects"};
    if (portalViews.includes(route)) return {view: route};
    if (route === "report" || (route === "studio" && /^[a-f0-9]{32}$/.test(detail.split("?")[0]) && !projectId)) return {view:"report", detail};
    if (route === "issues" && !projectId && new URLSearchParams(detail.split("?")[1]).get("scope") === "all") return {view:route, detail};
    if (!projectId) return {view: "projects"};
    if (!route || route === "overview") return {view:"projects"};
    if (projectViews.includes(route)) return {view:route, detail};
  }
  const view = ["report", "journal", ...workspaceViews].includes(route) ? route : "studio";
  return {view, detail};
}

function updateNavigation(view) {
  const loggedIn = mode === "local" || Boolean(viewer);
  navigation.hidden = !loggedIn;
  controls.hidden = !viewer;
  accountEditor.refresh();
  menu.hidden = !loggedIn;
  const selected = {studio:"scenarios", issues:"projects", release:"projects", analytics:"projects",
    repository:"projects", journal:"projects", report:"projects", runs:"projects", outbox:"projects"}[view] || view;
  navigation.querySelectorAll("[data-view]").forEach(link => {
    link.hidden = (link.hasAttribute("data-portal-view") && mode !== "production") ||
      (link.hasAttribute("data-project-view") && mode === "production" && !projectId);
    if (link.dataset.view === selected) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  menu.textContent = (navigation.querySelector('[aria-current="page"]')?.textContent || "Разделы") + " ▾";
  setProjectChoices(projects);
  shareProject.hidden = !projectId;
  document.querySelector("#reader-mode").hidden = !workspace || canWrite();
}

function authHeading(title, description, fields) {
  return '<section class="panel auth-card"><header><h1>' + escape(title) + '</h1><p>' + escape(description) +
    '</p></header>' + fields + '</section>';
}

const loginFields = '<label class="field">Логин<input name="username" required maxlength="64" autocomplete="username" autocapitalize="off" spellcheck="false"></label>' +
  '<label class="field">Пароль<input name="password" type="password" required maxlength="128" autocomplete="current-password"></label>';

const newAccountFields = String.raw`
  <label class="field">Имя в проекте<input name="displayName" required maxlength="100" pattern=".*\S.*" title="Введите имя" autocomplete="name"></label>
  <div class="field"><label for="account-username">Логин</label>
    <input id="account-username" name="username" required maxlength="64" pattern="[A-Za-z0-9_.\-]+" autocomplete="username"
      autocapitalize="off" spellcheck="false" aria-describedby="username-hint">
    <small id="username-hint">До 64 символов. Подойдут латинские буквы, цифры, точка, дефис и подчёркивание.</small></div>
  <div class="field"><label for="account-password">Пароль</label>
    <input id="account-password" name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password" aria-describedby="password-hint">
    <small id="password-hint">От 12 до 128 символов.</small></div>
  <fieldset class="account-agreements"><legend>Документы сервиса</legend><small>Сейчас опубликованы страницы-заглушки.</small>
    <label><input type="checkbox" required name="terms"> <span>Принимаю <a href="/legal/terms" target="_blank" rel="noopener">условия использования</a>.</span></label>
    <label><input type="checkbox" required name="privacy"> <span>Ознакомился с <a href="/legal/privacy" target="_blank" rel="noopener">политикой конфиденциальности</a>.</span></label>
    <label><input type="checkbox" required name="personal-data"> <span>Даю <a href="/legal/personal-data" target="_blank" rel="noopener">согласие на обработку персональных данных</a>.</span></label>
  </fieldset>`;

function authForm(action, fields, button, after = "") {
  return '<form id="account-form" data-operation="' + action + '">' + fields +
    '<p role="alert" class="run-error"></p><div class="page-actions"><button class="button primary" type="submit">' +
    button + '</button>' + after + '</div></form>';
}

async function showAuth(view, token) {
  const revision = ++authRevision;
  const inviteLink = location.hash.startsWith("#invite/");
  if (view === "login") {
    const back = inviteLink ? '<button type="button" class="link-button" data-auth="invite">К приглашению</button>' : "";
    const reportLink=/^#(?:report|studio|scenarios(?:\/automation)?)\/[a-f0-9]{32}(?:\?|$)/.test(location.hash);
    page.innerHTML = authHeading("Вход в «Штопку»", reportLink
      ? "Войдите под учётной записью участника проекта. После входа откроется проверка по ссылке."
      : "Войдите, чтобы открыть проекты своего предприятия.",
      authForm("login", loginFields, "Войти", back) + '<p class="auth-switch"><a href="/recover">Забыли пароль?</a></p>' + (inviteLink ? "" :
        '<p class="auth-switch">Нет аккаунта? <a href="#register">Зарегистрироваться</a></p>'));
    page.setAttribute("aria-busy", "false");
    return;
  }
  if (view === "register") {
    const returnHash = history.state?.loginHash?.startsWith("#") ? history.state.loginHash : "#login";
    page.innerHTML = authHeading("Регистрация", "Создайте аккаунт, чтобы открыть первый проект и проверить свой код.",
      authForm("register", newAccountFields, "Создать аккаунт") +
      `<p class="auth-switch">Уже есть аккаунт? <a href="${escape(returnHash)}">Войти</a></p>`);
    page.setAttribute("aria-busy", "false");
    return;
  }
  page.setAttribute("aria-busy", "true");
  page.innerHTML = authHeading("Приглашение", "Проверяем ссылку…", "");
  try {
    const {invite} = await request("/api/invite/inspect", {token});
    if (revision !== authRevision) return;
    const roles = {manager: "Руководитель проекта", editor: "Редактор", reader: "Читатель",
      member: "Сотрудник", moderator: "Модератор", owner: "Владелец"};
    const name = [invite.organizationName, invite.projectName, roles[invite.projectRole || invite.organizationRole]]
      .filter(Boolean).join(" · ");
    const fields = viewer ? '<p>Вы вошли как <strong>' + escape(viewer.displayName) + '</strong>.</p>' : newAccountFields;
    const login = viewer ? "" : '<button type="button" class="link-button" data-auth="login">У меня есть аккаунт</button>';
    const destination = invite.projectName ? '<p>После принятия откроется проект <strong>'+escape(invite.projectName)+'</strong>. Позже его можно открыть через вкладку «Проекты».</p>' : "";
    page.innerHTML = authHeading("Приглашение", name,
      destination + authForm("invite", fields, viewer ? "Принять и открыть проект" : "Создать аккаунт и принять", login));
  } catch (error) {
    if (revision === authRevision) {
      page.innerHTML = authHeading("Приглашение", error.message,
        '<div class="invite-recovery"><p>Уже приняли приглашение? Откройте свои проекты под созданным аккаунтом.</p><div class="portal-actions"><a class="button" href="#projects">Мои проекты</a></div></div>');
    }
  } finally {
    if (revision === authRevision) page.setAttribute("aria-busy", "false");
  }
}

function render(polling = false) {
  const {view, detail} = currentRoute();
  guide.visit(view, viewer?.username || (mode === "local" ? "local" : ""), detail || "");
  updateNavigation(view);
  main.classList.toggle("garden-home", ["overview", "login", "register", "invite"].includes(view));
  const screenKey = view + "/" + (detail || "");
  if (["report", "studio", "journal"].includes(view) || portalViews.includes(view) || projectViews.includes(view)) {
    if (!polling && portalView !== screenKey) {
      studio.leave();
      journal.leave();
      projectScreens.leave();
      release.leave();
      portal.leave();
      portalView = screenKey;
      renderedPage = null;
      if (view === "report" && mode === "production" && !projectId) {
        page.setAttribute("aria-busy","false");
        page.innerHTML='<section class="panel auth-card"><h1>Нужен доступ к проекту</h1><p>Попросите руководителя пригласить вас в проект с этим отчётом или войдите под учётной записью участника.</p><a href="#projects">Мои проекты</a></section>';
      } else if (view === "report") studio.openReport(detail);
      else if (view === "studio") studio.open(detail);
      else if (view === "journal") journal.open(detail || "all");
      else if (portalViews.includes(view)) portal.render(view);
      else if (view === "release") release.render(detail);
      else projectScreens.render(view, detail);
    }
    return;
  }
  if (portalView) {
    studio.leave();
    journal.leave();
    projectScreens.leave();
    release.leave();
    portal.leave();
    portalView = null;
  }
  const key = view === "login" ? `login/${location.hash}` : screenKey;
  if (["invite", "login", "register"].includes(view)) {
    if (!polling && renderedPage?.key !== key) {
      renderedPage = {key};
      showAuth(view, detail);
    }
    return;
  }
  if (!workspace) return;
  const data = detail ? [runById(detail), detailError] : workspace.runs;
  const signature = JSON.stringify([data, workspace.settings, workspace.runs.length]);
  const samePage = renderedPage?.key === key;
  if (polling && samePage && (
    signature === renderedPage.signature || dialog.open || page.contains(document.activeElement)
  )) return;
  const expanded = samePage ? [...page.querySelectorAll(".finding")].map(item => [item.dataset.detail, item.open]) : [];
  renderedPage = {key, signature};
  const pages = {runs: renderRuns, outbox: renderOutbox};
  page.innerHTML = pages[view](detail);
  const openById = new Map(expanded);
  page.querySelectorAll(".finding").forEach(item => {
    if (openById.has(item.dataset.detail)) item.open = openById.get(item.dataset.detail);
  });
  page.setAttribute("aria-busy", "false");
}

async function loadDetail() {
  const {view, detail} = currentRoute();
  if (!workspace || view === "studio" || !workspaceViews.includes(view) || !detail || !asynchronous()) return;
  if (!/^[a-f0-9]{32}$/.test(detail)) {
    detailError = "Запуск не найден.";
    return;
  }
  const marker = workspace.runs.find(run => run.id === detail)?.updatedAt ?? null;
  if (selectedRun?.id === detail && detailMarker === marker) return;
  const started = mutation;
  const read = ++detailRead;
  const isCurrent = () => read === detailRead && started === mutation && currentRoute().detail === detail;
  try {
    const run = await request(`/api/runs/${detail}`);
    if (isCurrent()) {
      selectedRun = run;
      detailMarker = marker;
      detailError = null;
    }
  } catch (error) {
    if (isCurrent()) {
      selectedRun = null;
      detailError = error.message;
    }
  }
}

async function poll() {
  if (!workspace || currentRoute().view === "studio" || !asynchronous() || !workspaceViews.includes(currentRoute().view) ||
    document.hidden || pollInFlight || requestInFlight) return;
  pollInFlight = true;
  const started = mutation;
  try {
    const fresh = await request("/api/workspace");
    if (started !== mutation) return;
    const draft = needsSave() ? workspace.draft : fresh.draft;
    savedDraft = structuredClone(fresh.draft);
    workspace = {...fresh, draft};
    await loadDetail();
    if (started === mutation) render(true);
  } catch {
    // Keep the current page available during a temporary connection failure.
  } finally {
    pollInFlight = false;
  }
}

async function navigate() {
  if (!mode) return;
  if (mode === "production" && viewer && ["#login", "#register"].includes(location.hash)) {
    history.replaceState(null, "", "#projects");
  }
  if (currentRoute().view !== "invite") authRevision++;
  detailError = null;
  render();
  await loadDetail();
  render(true);
}

function dialogEditors() {
  const group = dialog.querySelector(".source-editors");
  const mode = dialog.querySelector('[name="customMode"]').value;
  const bound = dialogContext.repositories.find(item => "@bound:" + item.bindingId === mode);
  group.querySelectorAll("[data-custom-group]").forEach(panel => {
    panel.hidden = panel.disabled = panel.dataset.customGroup !== (bound ? "github" : mode);
  });
  dialogContext.github.setSource(Boolean(bound) || mode === "github",
    bound?.repository, bound ? mode : "");
  dialog.querySelector("#source-info").textContent = mode === "paste"
      ? "Для выбранных файлов применяются правила Python и JSON. В отчёте будут пути и строки с замечаниями."
      : "Один запуск проверит состав репозитория, текстовые файлы и поддерживаемые типы кода, настроек и зависимостей. Охват будет указан в отчёте.";
}

function openRun(runId, preview = false) {
  const published = workspace.version;
  const previous = runById(runId);
  const gitSource = previous?.lineage?.startsWith("github-read:");
  const repositories = workspace.settings.boundRepositories || [];
  const previousBinding = gitSource && (previous.sourceBinding
    ? repositories.find(item => "@bound:" + item.bindingId === previous.sourceBinding)
    : repositories.find(item => item.repository.toLowerCase() === previous.source.toLowerCase()));
  const missingBinding = gitSource && previous.sourceBinding && !previousBinding;
  const isCustom = gitSource || previous?.source === "Пользовательский снимок";
  dialogContext = {
    runId, preview, repositories,
    requestId: globalThis.crypto?.randomUUID?.()
  };
  dialog.innerHTML = `
    <form id="run-form">
      <header class="panel-head"><div><h2 id="dialog-title">${preview ? "Проверка черновика" : runId ? "Повторная проверка" : "Запустить проверку"}</h2>
        <p>${preview ? `Сохранённый черновик «${escape(savedDraft.name)}». Результат останется в истории.`
          : `Опубликованная версия v${published.number}. ${escape(published.spec.name)}`}</p></div></header>
      <div class="dialog-body">
        <p id="source-info" class="fine-print"></p>
        ${ruleScope(preview ? savedDraft : published.spec)}
        ${!preview && published.spec.trigger === "push" ? `<label class="field">Событие
          <select name="origin"><option value="manual">Ручной запуск</option><option value="push">Имитировать push</option></select>
        </label>` : ""}
        <fieldset class="source-editors source-inputs">
          <label class="field">Где находится проект?<select name="customMode">
            ${missingBinding ? '<option value="" disabled>Исходный репозиторий отключён — выберите источник</option>' : ""}
            ${boundSourceOptions(repositories, escape)}
            <option value="github">Указать ссылку на GitHub</option><option value="folder">Папка на компьютере</option>
            <option value="zip">ZIP-архив проекта</option><option value="files">Отдельные файлы</option><option value="paste">Вставить текст</option>
          </select></label>
          <fieldset class="source-inputs" data-custom-group="github">${githubFields()}</fieldset>
          <fieldset class="source-inputs" data-custom-group="folder"><label class="field">Папка проекта<input name="folder" type="file" webkitdirectory multiple required></label>
            <p class="fine-print">Пути сохраняются от корня папки. В проверку попадут текстовые файлы. Для файлов ключей, локальных секретов и двоичных файлов учитывается имя.</p></fieldset>
          <fieldset class="source-inputs" data-custom-group="zip"><label class="field">ZIP-архив до 8 МБ<input name="zip" type="file" accept=".zip" required></label></fieldset>
          <fieldset class="source-inputs" data-custom-group="files"><label class="field">Файлы проекта<input name="files" type="file" multiple required></label>
            <p class="fine-print">Можно выбрать несколько файлов. Для вложенных модулей выберите папку целиком.</p></fieldset>
          <fieldset class="source-inputs" data-custom-group="paste"><label class="field">service.py<textarea name="python" maxlength="30000" spellcheck="false"></textarea></label>
            <label class="field">settings.json<textarea name="config" maxlength="30000" spellcheck="false"></textarea></label></fieldset>
        </fieldset>
        ${!preview && isDirty() ? '<p class="fine-print">Для запуска с изменениями сначала опубликуйте черновик.</p>' : ""}
        <p role="alert" class="run-error"></p>
      </div>
      <footer class="dialog-footer"><button type="button" class="button" data-action="cancel-run">Отмена</button>
        <button type="submit" class="button primary">Запустить</button></footer>
    </form>`;
  if (gitSource) {
    dialog.querySelector('[name="customMode"]').value = previousBinding ? "@bound:" + previousBinding.bindingId : missingBinding ? "" : "github";
  }
  if (isCustom && !gitSource) dialog.querySelector('[name="customMode"]').value = "folder";
  dialogContext.github = mountGithub(dialog.querySelector("form"), {request, project:projectId || "default",
    bindingAvailable:mode === "production", initialRepository:gitSource ? previous.source : "", allowEmpty:true});
  dialogEditors();
  dialog.showModal();
}

function triageFields(status) {
  const details = dialog.querySelector(".decision-fields");
  details.hidden = details.disabled = status === "open";
}

function openTriage(runId, findingId) {
  const finding = runById(runId)?.findings?.find(item => item.id === findingId);
  if (!finding) return;
  const decision = finding.triageDecision;
  const today = new Date().toISOString().slice(0, 10);
  const latest = new Date(Date.now() + 365 * 86_400_000).toISOString().slice(0, 10);
  dialogContext = {runId, findingId};
  dialog.innerHTML = `<form id="triage-form">
    <header class="panel-head"><div><h2 id="dialog-title">Решение по замечанию</h2><p>${escape(finding.title)}</p></div></header>
    <div class="dialog-body">
      <label class="field">Статус<select name="status">${Object.entries(triageLabels).map(([key, label]) =>
        `<option value="${key}" ${finding.triage === key ? "selected" : ""}>${label}</option>`).join("")}</select></label>
      <fieldset class="decision-fields">
        <label class="field">Причина<textarea name="reason" rows="3" minlength="3" maxlength="300" required>${escape(decision?.reason)}</textarea></label>
        <label class="field">Дата пересмотра<input type="date" name="expiresAt" min="${today}" max="${latest}"
          value="${escape(decision?.expiresAt || today)}" required></label>
      </fieldset>
      <p role="alert" class="run-error"></p>
    </div>
    <footer class="dialog-footer"><button type="button" class="button" data-action="cancel-run">Отмена</button>
      <button type="submit" class="button primary">Сохранить решение</button></footer>
  </form>`;
  triageFields(finding.triage);
  dialog.showModal();
}

async function withRequest(action, errorHandler) {
  if (requestInFlight) return;
  requestInFlight = true;
  mutation++;
  try {
    await action();
  } catch (error) {
    if (errorHandler) errorHandler(error);
    else announce(error.message, true);
  } finally {
    requestInFlight = false;
  }
}

function setRun(run) {
  const index = workspace.runs.findIndex(item => item.id === run.id);
  let summary = run;
  if (asynchronous()) {
    selectedRun = run;
    detailMarker = undefined;
    const {findings, stages, fixed, coverage, diagnostics, ...metadata} = run;
    summary = {...metadata, diagnosticCount: diagnosticCount(run), findingCount: findings.length,
      highCount: findings.filter(item => item.level === "high").length};
  }
  if (index < 0) workspace.runs = [summary, ...workspace.runs].slice(0, 50);
  else workspace.runs[index] = summary;
}

document.querySelector(".skip-link").addEventListener("click", event => {
  event.preventDefault();
  main.focus();
});

document.addEventListener("click", event => {
  const button = event.target.closest("button");
  if (button?.dataset.action === "account-logout") { signOut.click(); return; }
  if (!button || !workspace) return;
  const action = button.dataset.action;
  if (requestInFlight) return;
  if (action === "cancel-run") dialog.close();
  if (!canWrite()) return;
  if (action === "simulate-policy") release.simulate();
  if (action === "simulate-rescan") {
    withRequest(async () => {
      if (needsSave()) savedDraft = await request("/api/draft", structuredClone(workspace.draft));
      release.leave();
      openRun(undefined, true);
    });
  }
  if (action === "open-run" || action === "repeat") openRun(button.dataset.run);
  if (action === "edit-triage") openTriage(button.dataset.run, button.dataset.finding);
  if (action === "retry-delivery") {
    const channel = button.dataset.channel;
    button.disabled = true;
    withRequest(async () => {
      const run = await request("/api/delivery/retry", {runId: button.dataset.run, channel});
      setRun(run);
      render();
      const delivery = channel === "github" ? run.githubCheck : run.delivery;
      announce(delivery.message, !["queued", "sent"].includes(delivery.status));
    }).finally(() => {button.disabled = false;});
  }

});

page.addEventListener("change", event => {
  if (!workspace || !canWrite()) return;
  const field = event.target;
  const {triage, run} = field.dataset;
  if (triage) {
    field.disabled = true;
    withRequest(async () => {
      setRun(await request("/api/triage", {runId: run, findingId: triage, status: field.value}));
      announce("Решение сохранено");
    }, error => {
      field.value = runById(run)?.findings.find(item => item.id === triage)?.triage || "open";
      announce(error.message, true);
    }).finally(() => {field.disabled = false;});
  }
});

dialog.addEventListener("change", async event => {
  if (event.target.name === "customMode") dialogEditors();
  if (event.target.name === "status") triageFields(event.target.value);
});
dialog.addEventListener("cancel", event => {
  if (requestInFlight) event.preventDefault();
});

async function customInput(form) {
  const fields = form.elements, kind = fields.customMode.value;
  if (!kind) throw Error("Выберите источник для повторной проверки.");
  if (kind === "github" || kind.startsWith("@bound:")) return githubSelection(form);
  if (kind === "zip") return {archive:await archiveBase64(fields.zip.files[0])};
  if (kind === "paste") {
    const files = Object.fromEntries([["service.py", fields.python.value], ["settings.json", fields.config.value]].filter(([,value])=>value.trim()));
    if (!Object.keys(files).length) throw Error("Вставьте код Python или настройки JSON.");
    return {files};
  }
  return projectUpload(fields[kind].files, workspace.sourcePolicy, kind === "folder");
}

function submitRun(form) {
  const button = form.querySelector('[type="submit"]');
  const formData = new FormData(form);
  const payload = {
    preset: "custom",
    origin: formData.get("origin") || "manual",
    baselineId: dialogContext.runId,
    preview: dialogContext.preview || undefined
  };
  button.disabled = true;
  button.textContent = asynchronous() ? "Добавляем в очередь…" : "Проверяем…";
  form.querySelector(".run-error").textContent = "";
  withRequest(async () => {
    Object.assign(payload, await customInput(form));
    const signature = JSON.stringify(payload);
    if (dialogContext.signature && dialogContext.signature !== signature) dialogContext.requestId = globalThis.crypto?.randomUUID?.();
    dialogContext.signature = signature;
    if (asynchronous() && dialogContext.requestId) payload.requestId = dialogContext.requestId;
    const run = await request("/api/runs", payload);
    setRun(run);
    dialog.close();
    if (location.hash === runHref(run)) render();
    else location.hash = runHref(run);
    announce(isActive(run) ? "Проверка добавлена в очередь" : "Проверка завершена");
  }, error => {
    form.querySelector(".run-error").textContent = error.message;
  }).finally(() => {
    button.disabled = false;
    button.textContent = "Запустить";
  });
}

function submitTriage(form) {
  const button = form.querySelector('[type="submit"]');
  const data = Object.fromEntries(new FormData(form));
  const payload = {...data, runId: dialogContext.runId, findingId: dialogContext.findingId};
  button.disabled = true;
  form.querySelector(".run-error").textContent = "";
  withRequest(async () => {
    const run = await request("/api/triage", payload);
    setRun(run);
    dialog.close();
    render();
    const openedFinding = [...page.querySelectorAll(".finding")].find(item => item.dataset.detail === payload.findingId);
    openedFinding?.querySelector('[data-action="edit-triage"]')?.focus();
    announce("Решение сохранено");
  }, error => {
    form.querySelector(".run-error").textContent = error.message;
  }).finally(() => {button.disabled = false;});
}

dialog.addEventListener("submit", event => {
  event.preventDefault();
  if (requestInFlight || !canWrite()) return;
  if (event.target.id === "triage-form") submitTriage(event.target);
  else submitRun(event.target);
});

window.addEventListener("hashchange", ({oldURL}) => {
  if (mode === "production" && !viewer && location.hash === "#register" && !history.state?.loginHash) {
    const previous = new URL(oldURL).hash;
    if (previous && !previous.startsWith("#invite")) history.replaceState({loginHash: previous}, "");
  }
  loginForInvite = false;
  navigate();
});
page.addEventListener("focusout", () => window.setTimeout(() => render(true), 0));
dialog.addEventListener("close", () => render(true));

async function initialize() {
  const session = await request("/api/session");
  mode = session.mode;
  policyVersion = session.policyVersion;
  viewer = session.viewer;
  projects = session.projects || [];
  const requested = new URLSearchParams(location.search).get("project");
  const selected = projects.find(project => project.id === (requested || "default"));
  projectId = selected?.id || (!requested ? projects[0]?.id : undefined);
  if (viewer && requested && !projectId) announce("У вас нет доступа к этому проекту.", true);
  if (mode === "local" || projectId) {
    try {
      workspace = await request("/api/workspace");
      savedDraft = structuredClone(workspace.draft);
    } catch (error) {
      if (viewer || mode === "local") throw error;
    }
  }
  await navigate();
}

function signedOut() {
  studio.clear();
  release.leave();
  projectScreens.leave();
  closeMenu();
  viewer = null;
  accountEditor.reset();
  projects = [];
  projectId = undefined;
  workspace = undefined;
  selectedRun = undefined;
  renderedPage = null;
  mutation++;
  detailRead++;
  if (dialog.open) dialog.close();
  navigate();
}

page.addEventListener("click", event => {
  const file = event.target.closest("[data-report-download]");
  if (file) {
    event.preventDefault();
    download(file.href).catch(error => announce(error.message, true));
  }
  const action = event.target.closest("[data-auth]")?.dataset.auth;
  if (action) {
    loginForInvite = action === "login";
    navigate();
  }
});

page.addEventListener("submit", async event => {
  const form = event.target;
  if (form.id !== "account-form") return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]');
  if (button.disabled) return;
  button.disabled = true;
  const label = button.textContent;
  const errorText = form.querySelector('[role="alert"]');
  errorText.textContent = "";
  form.setAttribute("aria-busy", "true");
  const operation = form.dataset.operation;
  if (operation === "register") button.textContent = "Создаём аккаунт…";
  const fields = Object.fromEntries(new FormData(form));
  if (form.querySelector(".account-agreements")) {
    fields.policyVersion = policyVersion;
    fields.agreements = {};
    for (const input of form.querySelectorAll('.account-agreements input')) {
      fields.agreements[input.name] = input.checked;
      delete fields[input.name];
    }
  }
  try {
    if (operation === "login") {
      await request("/api/login", fields);
      loginForInvite = false;
      renderedPage = null;
      await initialize();
    } else {
      const result = operation === "register" ? await request("/api/register", fields) :
        await request("/api/invite/accept", {...fields, token: currentRoute().detail});
      const url = new URL(location.pathname, location.origin);
      if (result.projectId) url.searchParams.set("project", result.projectId);
      url.hash = "projects";
      history.replaceState(null, "", url);
      location.reload();
      return;
    }
  } catch (error) {
    errorText.textContent = error instanceof TypeError ? "Не удалось связаться с сервером. Проверьте соединение и повторите попытку." : error.message;
  }
  form.setAttribute("aria-busy", "false");
  button.textContent = label;
  button.disabled = false;
});

page.addEventListener("change", event => {
  const projectSwitcher = event.target;
  if (projectSwitcher.id !== "project-switcher") return;
  if ((studio.dirty() || workspace && needsSave()) && !window.confirm("При смене проекта несохранённые изменения черновика будут потеряны. Продолжить?")) {
    projectSwitcher.value = projectId;
    return;
  }
  const url = new URL(location.href);
  url.searchParams.set("project", projectSwitcher.value);
  const {view} = currentRoute();
  url.hash = {issues:"projects/issues",release:"projects/releases",repository:"projects/repositories",
    journal:"projects/journal",analytics:"projects/analytics"}[view] || "projects";
  location.assign(url);
});
shareProject.addEventListener("click", () => portal.share());
signOut.addEventListener("click", async () => {
  signOut.disabled = true;
  try {
    await request("/api/logout", {});
    signedOut();
  } catch (error) {
    announce(error.message, true);
  } finally {
    signOut.disabled = false;
  }
});

initialize().catch(error => {
  page.setAttribute("aria-busy", "false");
  page.innerHTML = `<p class="empty">${escape(error.message)}</p>`;
});
window.setInterval(poll, 3000);
