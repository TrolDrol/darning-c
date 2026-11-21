import {projectRoute, projectTabs} from "/project_hub.js";

const esc = value => String(value ?? "").replace(/[&<>"']/g, char =>
  ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char]));
const finished = run => ["passed", "review", "partial", "skipped"].includes(run.status);
const stamp = value => new Date(value).toLocaleString("ru-RU", {dateStyle: "short", timeStyle: "short"});
const versionLabel = run => run.origin === "automation" ? "Схема " + String(run.workflow.number).slice(0,9) :
  (run.workflow.preview ? "Предпросмотр" : "v" + run.workflow.number);
const runName = run => [stamp(run.createdAt), run.source, versionLabel(run),
  run.revision?.slice(0, 9), run.id.slice(0, 6), run.status === "skipped" ? "Без анализа содержимого" : ""].filter(Boolean).join(" · ");
const gates = {disabled: "Отключено", passed: "Пройдено", blocked: "Требует исправления", insufficient: "Недостаточно данных"};
const triage = {accepted: "Риск принят", false_positive: "Ложное срабатывание", open: "Открыто"};
const levels = {high: "Высокая", medium: "Средняя"};
const stages = {done: "Проверен", error: "Ошибка", skipped: "Пропущен", unknown: "Охват неизвестен"};
const groups = {new: "Новые", existing: "Сохранились", fixed: "Исправлены", unverified: "Требуют проверки"};
const option = (value, label, selected) => `<option value="${esc(value)}" ${selected ? "selected" : ""}>${esc(label)}</option>`;

export function gateFields(spec) {
  const value = spec.gateMinimum || "off";
  return `<label class="field">Требуют исправления<select data-setting="gateMinimum">
    ${[["off", "Условие отключено"], ["high", "Новые замечания высокой важности"],
      ["medium", "Все новые замечания"]].map(([key, label]) => option(key, label, key === value)).join("")}</select></label>
    <p class="fine-print">Действующие решения о принятии риска и ложных срабатываниях учитываются при оценке.</p>`;
}

export function gateResult(gate, label = "Условия приёмки") {
  if (!gate) return "";
  return `<div class="summary-strip"><strong>${esc(label)}</strong>
    <span class="chip ${({blocked: "red", insufficient: "amber", disabled: "neutral"})[gate.status] || ""}">${esc(gates[gate.status])}</span>
    <span>${esc(gate.reason)}</span></div>`;
}

function sameSource(first, second) {
  const id = run => run.repositoryId || /^github:(\d+):/.exec(run.lineage || "")?.[1];
  if (id(first) && id(second)) return id(first) === id(second);
  if (first.repository || second.repository) return first.repository?.toLowerCase() === second.repository?.toLowerCase();
  return (first.lineage || first.source) === (second.lineage || second.source);
}

function currentDecision(item) {
  if (!("currentTriage" in item || "assignee" in item)) return "";
  return `<p>Сейчас в проекте · ${esc(triage[item.currentTriage] || "—")}
    · Ответственный · ${esc(item.assignee || "не назначен")}
    ${item.currentDecision?.expiresAt ? ` · Пересмотр до ${esc(item.currentDecision.expiresAt)}
      · ${esc(item.currentDecision.reason)}` : ""}</p>`;
}

function entries(items, exceptions = false) {
  if (!items.length) return "";
  return `<ul>${items.map(item => `<li><strong>${item.issueId
      ? `<a href="#projects/issues/${encodeURIComponent(item.issueId)}">${esc(item.title)}</a>` : esc(item.title)}</strong> · ${esc(item.ruleId)} · ${esc(levels[item.level] || item.level)}
      <p><code>${esc(item.file)}</code>${item.line ? `, строка ${esc(item.line)}` : ""}</p>
      ${exceptions ? `<p>${esc(triage[item.triage])} · ${esc(item.triageDecision?.reason)}
        · пересмотр до ${esc(item.triageDecision?.expiresAt)}</p>` : ""}${currentDecision(item)}</li>`).join("")}</ul>`;
}

function showComparison(report) {
  const coverage = side => report.coverage[side].map(item => `<li><code>${esc(item.file)}</code>
      · ${esc(stages[item.status] || item.status)} · ${esc(item.rules.join(", "))}</li>`).join("") || "<li>Нет файлов с подтверждённым охватом.</li>";
  return `<section class="portal-tile"><header class="portal-tile-head"><h2>Решение по релизу</h2>
      <div class="portal-actions"><button class="button" data-release-export="html">Скачать отчёт HTML</button>
      <button class="button" data-release-export="json">JSON</button></div></header>
      ${gateResult(report.gate, "По выбранной паре версий")}
      ${report.recordedGate ? `<details><summary>Решение при завершении запуска</summary>${gateResult(report.recordedGate)}</details>` : ""}
      <dl class="portal-tiles">${Object.entries(groups).map(([key, label]) =>
        `<div class="portal-metric"><dt>${label}</dt><dd>${report.groups[key].length}</dd></div>`).join("")}</dl>
      ${Object.entries(groups).filter(([key]) => report.groups[key].length).map(([key, label]) =>
        `<details ${key === "new" ? "open" : ""}><summary>${label} · ${report.groups[key].length}</summary>${entries(report.groups[key])}</details>`).join("")}
      <details><summary>Действующие исключения · ${report.exceptions.length}</summary>${entries(report.exceptions, true)}</details></section>
      <section class="portal-tile"><h2>Охват проверки</h2><div class="portal-two-col">
      <div><h3>Базовая версия</h3><ul>${coverage("base")}</ul></div>
      <div><h3>Проверяемая версия</h3><ul>${coverage("head")}</ul></div></div></section>`;
}

function showSimulation(result) {
  if (result.needsScan) return `<p role="status">${esc(result.reason)}</p>
    ${result.addedRules.length ? `<p>Добавлены правила · ${esc(result.addedRules.join(", "))}</p>` : ""}
    ${result.removedRules.length ? `<p>Убраны правила · ${esc(result.removedRules.join(", "))}</p>` : ""}
    <button type="button" class="button" data-action="simulate-rescan">Сохранить черновик и проверить файлы</button>`;
  const delivery = result.delivery;
  const labels = {planned: "Предусмотрена", disabled: "Отключена", skipped: "Пропущена", unavailable: "Недоступна"};
  return `${gateResult(result.gate)}<h3>Доставка · ${esc(labels[delivery.status])}</h3><p>${esc(delivery.reason)}</p>
      <p>Совпадений · ${esc(delivery.count)}</p>${delivery.status === "planned" ? `<p>Получатель · ${esc(delivery.recipient)}
        · ${delivery.channel === "smtp" ? esc(delivery.address) : "Локальная сводка"}</p>` : ""}
      ${delivery.partial ? "<p>Расчёт охватывает только проверенные файлы запуска.</p>" : ""}`;
}

export function createRelease({page, request, getProjectId, getWorkspace, download}) {
  let revision = 0;
  let runs = [];
  let completed;
  let repository;
  const dialog = document.createElement("dialog");
  dialog.className = "portal-dialog";
  dialog.setAttribute("aria-labelledby", "policy-title");
  document.body.append(dialog);
  const scoped = (name, params = {}) => "/api/" + name + "?" + new URLSearchParams({project: getProjectId(), ...params});

  function leave() {
    revision++;
    if (dialog.open) dialog.close();
    completed = null;
  }

  function selectBase() {
    const form = page.querySelector("[data-release-form]");
    if (!form) return;
    const head = runs.find(run => run.id === form.elements.head.value);
    const options = head ? runs.filter(run => run.id !== head.id && run.createdAt <= head.createdAt && sameSource(run,head)) : [];
    form.elements.base.innerHTML = options.length ? options.map(run => option(run.id, runName(run))).join("") :
      option("", "Нужна более ранняя проверка того же источника");
    form.elements.compare.disabled = !options.length;
  }

  async function render(detail) {
    leave();
    const marker = revision;
    repository = new URLSearchParams(detail || "").get("repository") || "";
    const heading = projectTabs("release",getProjectId()) + '<header class="portal-heading"><div><h1>Сравнение релизов</h1></div></header>';
    page.innerHTML = '<div class="portal">' + heading + '<p role="status">Загружаем проверки…</p></div>';
    try {
      const [data, sources] = await Promise.all([request(scoped("release/runs", repository ? {repository} : {})),
        request(scoped("project/sources"))]);
      if (marker !== revision) return;
      runs = data.runs;
      const names = sources.repositories;
      if (repository && !names.some(name=>name.toLowerCase()===repository.toLowerCase())) names.push(repository);
      const selector = `<div class="project-filters"><label class="field">Репозиторий<select data-release-repository>
        ${option("","Все источники проекта",!repository)}${names.map(name => option(name,name,name.toLowerCase()===repository.toLowerCase())).join("")}</select></label></div>`;
      const form = `<form class="portal-tile portal-stack" data-release-form>
        <label class="field">Проверяемая версия<select name="head">${runs.map(run => option(run.id, runName(run))).join("")}</select></label>
        <label class="field">Базовая версия<select name="base"></select></label>
        <div><button class="button primary" name="compare">Сравнить</button></div></form>`;
      const canSimulate = getWorkspace()?.settings.canWrite && runs.some(run => run.origin !== "automation" && finished(run));
      page.innerHTML = `<div class="portal">${heading}${selector}${runs.length < 2 ? '<p class="portal-tile">Для сравнения нужны две завершённые проверки одного источника. <a href="#runs">Открыть запуски</a></p>' : form}
        ${canSimulate ? '<button type="button" class="link-button" data-action="simulate-policy">Проверить условия приёмки на прошлом запуске</button>' : ""}
        <div class="portal-stack" data-release-out aria-live="polite"></div></div>`;
      selectBase();
    } catch (error) {
      if (marker === revision) page.innerHTML = `<div class="portal">${heading}<p role="alert">${esc(error.message)}</p></div>`;
    }
  }

  page.addEventListener("change", event => {
    if (event.target.matches("[data-release-repository]")) {
      location.hash=projectRoute("releases","",{repository:event.target.value});
      return;
    }
    const form = event.target.closest("[data-release-form]");
    if (!form) return;
    revision++;
    completed = null;
    page.querySelector("[data-release-out]").replaceChildren();
    if (event.target.name === "head") selectBase();
    else form.elements.compare.disabled = !form.elements.base.value;
  });

  page.addEventListener("submit", async event => {
    const form = event.target;
    if (!form.matches("[data-release-form]")) return;
    event.preventDefault();
    const marker = ++revision;
    const params = Object.fromEntries(new FormData(form));
    if (repository) params.repository = repository;
    const output = page.querySelector("[data-release-out]");
    form.elements.compare.disabled = true;
    output.textContent = "Сравниваем проверки…";
    try {
      const report = await request(scoped("release", params));
      if (marker !== revision) return;
      completed = params;
      output.innerHTML = showComparison(report);
    } catch (error) {
      if (marker === revision) output.textContent = error.message;
    } finally {
      if (marker === revision) form.elements.compare.disabled = false;
    }
  });

  page.addEventListener("click", async event => {
    const format = event.target.closest("[data-release-export]")?.dataset.releaseExport;
    if (!format || !completed) return;
    try {
      await download(scoped("release/export", {...completed, format}));
    } catch (error) {
      const output = page.querySelector("[data-release-out]");
      if (output) output.append(document.createTextNode(error.message));
    }
  });

  function simulate() {
    const workspace = getWorkspace();
    const options = runs.filter(run => run.origin !== "automation" && finished(run)).map(run => option(run.id, runName(run))).join("");
    dialog.innerHTML = `<header class="portal-dialog-header"><h2 id="policy-title">Проверить условия на прошлом запуске</h2>
      <button type="button" aria-label="Закрыть" data-release-close>×</button></header>
      <form class="dialog-body"><p>Расчёт использует текущий черновик и сохранённые результаты. Отправка и публикация отключены.</p>
      ${options ? `<label class="field">Проверка<select name="runId">${options}</select></label>${gateFields(workspace.draft)}
        <button class="button primary" type="submit">Рассчитать</button>` : "<p>Сначала завершите хотя бы одну проверку.</p>"}
      <div aria-live="polite" data-simulation-out></div></form>`;
    dialog.showModal();
  }
  dialog.addEventListener("click", event => {
    if (event.target.closest("[data-release-close]")) dialog.close();
  });
  dialog.addEventListener("change", () => {
    dialog.querySelector("[data-simulation-out]")?.replaceChildren();
  });
  dialog.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.target;
    const output = form.querySelector("[data-simulation-out]");
    const params = {runId: form.elements.runId.value, spec: {...getWorkspace().draft,
      gateMinimum: form.querySelector('[data-setting="gateMinimum"]').value}};
    const controls = [...form.elements];
    controls.forEach(control => { control.disabled = true; });
    output.textContent = "Рассчитываем результат…";
    try {
      output.innerHTML = showSimulation(await request(scoped("policy/simulate"), params));
    } catch (error) {
      output.textContent = error.message;
    } finally {
      controls.forEach(control => { control.disabled = false; });
    }
  });
  return {render, leave, simulate};
}
