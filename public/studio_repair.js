const activeRun = new Set(["queued", "running", "pending"]);
const activeRepair = new Set(["queued", "working", "verifying", "notifying", "accepting", "stopping"]);
const stateNames = {
  queued: "В очереди", working: "Готовится исправление", verifying: "Повторная проверка",
  notifying: "Отправляется уведомление", needs_decision: "Ожидает решения", remaining: "Есть замечания",
  ready: "Готово к слиянию", passed: "Проверка пройдена", accepting: "Слияние", accepted: "Влито",
  stopping: "Сеанс останавливается", stopped: "Остановлен", failed: "Ошибка",
  unchanged: "Правка не подготовлена", deleted: "Удалена",
};
const channelNames = {site: "На сайте", none: "Только на сайте", telegram: "Telegram", smtp: "Электронная почта", webhook: "HTTP-вебхук"};
const runIdPattern = /^[a-f0-9]{32}$/;
const findingIdPattern = /^[a-f0-9]{64}$/;
const repoPattern = /^[A-Za-z0-9-]+\/[\w.-]+$/;
const prPattern = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[\w.-]+\/pull\/\d+$/;
const findingId = finding => finding.repairId || finding.discussionKey || finding.findingId || finding.id;
const canChoose = finding => findingIdPattern.test(findingId(finding) || "") && finding.decision?.status !== "false_positive";
const stateLabel = status => stateNames[status] || "Ожидает обновления";
const defaultModelLabel = "Модель по умолчанию";
const disabledModelLabel = "Только алгоритмические правки";
const modelLabel = modelId => modelId === "@off" ? disabledModelLabel : modelId || defaultModelLabel;

function findingLabel(finding) {
  const place = [finding.path, finding.line].filter(Boolean).join(":");
  return [finding.title || finding.class || finding.category || "Замечание", place].filter(Boolean).join(" · ");
}

function reportLink(project, id) {
  return runIdPattern.test(id || "") ? "/?" + new URLSearchParams({project}) + "#report/" + id : "";
}

function optionRows(rows, defaultValue, escape) {
  return rows.map(({value, label}) =>
    `<option value="${escape(value)}"${value === defaultValue ? " selected" : ""}>${escape(label)}</option>`).join("");
}

export function mountRepair(host, {request, project, report, canWrite, announce, escape: e, focusFinding}) {
  if (activeRun.has(report.status) || !runIdPattern.test(report.id || "")) return () => {};
  const reportFindings = report.findings || [];
  const diagnostics = (report.repairDiagnostics || []).filter(canChoose);
  const findings = [...reportFindings.filter(canChoose), ...diagnostics];
  const writable = () => typeof canWrite === "function" ? canWrite() : Boolean(canWrite);
  if (!report.source?.bindingId && !report.repair?.sessionId && !(findings.length && writable())) return () => {};

  const panel = document.createElement("section");
  panel.className = "studio-repair";
  panel.setAttribute("aria-label", "Исправления");
  panel.hidden = true;
  panel.innerHTML = `<header class="repair-heading"><h3>Исправления</h3>
    <div class="repair-actions" data-repair-start-actions hidden>
      <button type="button" class="button" data-repair="selected" disabled>Исправить выбранные</button>
      <button type="button" class="button primary" data-repair="all">Исправить все</button>
    </div></header>
    <p class="repair-status" data-repair-status role="status"></p>
    <p class="repair-error" data-repair-error role="alert"></p>
    ${diagnostics.length ? `<section data-repair-diagnostics hidden><h4>Синтаксические ошибки</h4>
      <ul>${diagnostics.map(item => `<li>${e(findingLabel(item))}</li>`).join("")}</ul></section>` : ""}
    <div data-repair-sessions></div>`;
  const findingList = host.querySelector(".studio-findings");
  const findingHeading = findingList?.previousElementSibling;
  host.insertBefore(panel, findingHeading?.classList.contains("studio-report-heading") ? findingHeading : findingList);

  const url = "/api/studio/repair?" + new URLSearchParams({project, runId: report.id});
  const life = new AbortController(), selected = new Set(), rowActions = [];
  const actionBar = panel.querySelector("[data-repair-start-actions]");
  const allButton = panel.querySelector('[data-repair="all"]');
  const selectedButton = panel.querySelector('[data-repair="selected"]');
  const status = panel.querySelector("[data-repair-status]");
  const error = panel.querySelector("[data-repair-error]");
  const diagnosticSection = panel.querySelector("[data-repair-diagnostics]");
  const sessionList = panel.querySelector("[data-repair-sessions]");
  let data, modal, timer, readVersion = 0, pending = false, previousMarkup;

  function refreshSelection() {
    selectedButton.disabled = !selected.size;
    selectedButton.textContent = selected.size ? `Исправить выбранные (${selected.size})` : "Исправить выбранные";
    for (const row of rowActions) row.checkbox.checked = selected.has(row.key);
  }

  function showFindingActions(available) {
    if (diagnosticSection) diagnosticSection.hidden = !available;
    if (rowActions.length) {
      for (const row of rowActions) row.controls.hidden = !available;
      return;
    }
    if (!available) return;
    const rows = [
      ...Array.from(findingList?.children || [], (row, index) => [row, reportFindings[index]]),
      ...Array.from(diagnosticSection?.querySelector("ul").children || [], (row, index) => [row, diagnostics[index]]),
    ];
    rows.forEach(([row, finding]) => {
      if (!finding || !canChoose(finding)) return;
      const key = findingId(finding);
      const controls = document.createElement("div");
      controls.className = "repair-actions repair-finding-actions";
      controls.innerHTML = `<label class="repair-choice"><input type="checkbox" aria-label="${e("Выбрать · " + findingLabel(finding))}">Выбрать</label>
        <button type="button" class="link-button">Исправить</button>`;
      const checkbox = controls.querySelector("input");
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selected.add(key);
        else selected.delete(key);
        refreshSelection();
      }, {signal: life.signal});
      const button = controls.querySelector("button");
      button.addEventListener("click", () => showStart([key], button, findingLabel(finding)), {signal: life.signal});
      rowActions.push({key, checkbox, controls, button, label: findingLabel(finding)});
      row.append(controls);
    });
  }

  function external(href, label) {
    return `<a href="${e(href)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  }

  function roundLinks(round, session) {
    const links = [];
    const result = reportLink(project, round.runId);
    if (result) links.push(`<a href="${e(result)}">Отчёт проверки</a>`);
    const repository = session.repository || report.source?.repository;
    const commit = round.commit || round.revision;
    if (repoPattern.test(repository || "") && !/\/(?:\.|\.\.)$/.test(repository) && /^[a-f0-9]{40}$/.test(commit || "")) {
      links.push(external(`https://github.com/${repository}/commit/${commit}`, "Изменения"));
    }
    const pullRequest = round.prUrl || session.prUrl;
    if (prPattern.test(pullRequest || "")) links.push(external(pullRequest, "Открыть PR"));
    return links.length ? `<div class="repair-actions">${links.join("")}</div>` : "";
  }

  function roundMarkup(round, session) {
    const remaining = Number.isInteger(round.findingsCount) ? round.findingsCount : round.remaining?.length;
    const attempts = Array.isArray(round.changes) ? round.changes : [];
    const message = round.message || round.error;
    const modelDiagnostic = round.modelDiagnostic?.message;
    const delivery = round.notification;
    const deliveryState = {sent: "Уведомление принято", failed: "Уведомление не доставлено", skipped: "",
      unknown: "Статус доставки неизвестен", queued: "Уведомление в очереди", sending: "Отправляется уведомление"}[delivery?.status];
    return `<li class="repair-round"><div class="repair-heading">
      <strong>Раунд ${e(round.number)}</strong>
      <span class="chip">${e(stateLabel(round.status))}</span>
      ${round.status !== "failed" && Number.isInteger(remaining) ? `<small>Осталось замечаний · ${remaining}</small>` : ""}
    </div>
      ${round.branch && round.commit ? `<div class="repair-actions"><code>${e(round.branch)}</code>
        ${round.branchStatus === "deleted" ? "<small>Ветка удалена</small>" :
          round.branchStatus === "kept" ? "<small>Ветка сохранена</small>" : ""}</div>` : ""}
      ${message ? `<p>${e(message)}</p>` : ""}
      ${modelDiagnostic ? `<p><strong>${e(modelLabel(round.modelId))}</strong> · ${e(modelDiagnostic)}</p>` : ""}
      ${deliveryState ? `<small>${e(deliveryState)}${delivery.message ? " · " + e(delivery.message) : ""}</small>` : ""}
      ${roundLinks(round, session)}
      ${attempts.length ? `<details><summary>Работа над замечаниями (${attempts.length})</summary><ul>${attempts.map(item =>
        `<li>${e([item.title, item.path, item.reason || item.message || (item.method === "ai" ? "Предложила модель" : "Проверенная правка")].filter(Boolean).join(" · "))}</li>`).join("")}</ul></details>` : ""}
    </li>`;
  }

  function sessionMarkup(session) {
    const rounds = session.rounds || [], latest = rounds.at(-1);
    const button = (action, text, primary = false) =>
      `<button type="button" class="button${primary ? " primary" : ""}" data-repair="${action}" data-session="${e(session.id)}">${text}</button>`;
    const actions = writable() ? [
      session.canContinue && button("continue", latest?.status === "failed" ? "Повторить раунд" : "Продолжить"),
      session.canAccept && button("accept", "Влить в основную ветку", true),
      session.canStop && button("stop", "Остановить"),
    ].filter(Boolean).join("") : "";
    const original = session.originRunId !== report.id && reportLink(project, session.originRunId);
    return `<article class="repair-session"><header class="repair-heading">
        <strong>Сеанс ${e(String(session.id).slice(0, 8))}</strong>
        <span class="chip">${e(stateLabel(session.status))}</span>
        ${session.channel ? `<small>${e(channelNames[session.channel] || session.channel)}</small>` : ""}
        ${original ? `<a href="${e(original)}">Исходный отчёт</a>` : ""}
      </header>
      ${session.error ? `<p>${e(session.error)}</p>` : ""}
      ${latest ? `<ol class="repair-rounds">${roundMarkup(latest, session)}</ol>` : ""}
      ${rounds.length > 1 ? `<details data-round-history="${e(session.id)}"><summary>Предыдущие раунды (${rounds.length - 1})</summary>
        <ol class="repair-rounds">${rounds.slice(0, -1).reverse().map(round => roundMarkup(round, session)).join("")}</ol></details>` : ""}
      ${actions ? `<div class="repair-actions">${actions}</div>` : ""}
    </article>`;
  }

  function render() {
    const sessions = data.sessions || [];
    const hasSession = sessions.some(session => !["accepted", "stopped"].includes(session.status));
    const canStart = writable() && data.available && findings.length > 0 && !hasSession;
    const loading = sessions.some(session => activeRepair.has(session.status));
    panel.hidden = !sessions.length && !canStart && !(writable() && findings.length && data.reason);
    actionBar.hidden = !canStart;
    showFindingActions(canStart);
    const statusText = writable() && findings.length && !canStart && data.reason ? data.reason :
      loading ? "Состояние обновляется автоматически." : "";
    if (status.textContent !== statusText) status.textContent = statusText;
    const markup = sessions.map(sessionMarkup).join("");
    if (markup !== previousMarkup) {
      const expanded = new Set(Array.from(sessionList.querySelectorAll("[data-round-history][open]"), item => item.dataset.roundHistory));
      const focused = document.activeElement;
      sessionList.innerHTML = markup;
      for (const item of sessionList.querySelectorAll("[data-round-history]")) item.open = expanded.has(item.dataset.roundHistory);
      if (focused?.matches("button[data-session]") && !focused.isConnected) {
        [...sessionList.querySelectorAll("button[data-session]")].find(button =>
          button.dataset.repair === focused.dataset.repair && button.dataset.session === focused.dataset.session)?.focus({preventScroll: true});
      }
      previousMarkup = markup;
    }
    const requested = focusFinding;
    focusFinding = null;
    if (canStart && requested && !document.querySelector("dialog[open]")) {
      if (requested === "all") showStart(null, allButton);
      else if (findingIdPattern.test(requested)) {
        const action = rowActions.find(item => item.key === requested);
        if (action) showStart([action.key], action.button, action.label);
      }
    }
  }

  async function load() {
    clearTimeout(timer);
    if (pending || life.signal.aborted || !panel.isConnected) return;
    const version = ++readVersion;
    try {
      const response = await request(url, undefined, {signal: life.signal});
      if (version !== readVersion || life.signal.aborted) return;
      data = response;
      error.textContent = "";
      render();
    } catch (failure) {
      if (version === readVersion && !life.signal.aborted && writable() && findings.length) {
        panel.hidden = false;
        error.textContent = failure.message;
      }
    } finally {
      if (version === readVersion && !life.signal.aborted && panel.isConnected) {
        const sessions = data?.sessions || [];
        if (sessions.length || data?.available !== false && writable() && findings.length) {
          timer = window.setTimeout(load, sessions.some(session => activeRepair.has(session.status)) ? 3000 : 10000);
        }
      }
    }
  }

  function showDialog(title, opener, fields, label, makePayload, success, danger = false) {
    if (modal || !writable() || pending) return;
    const dialog = document.createElement("dialog");
    modal = dialog;
    dialog.className = "studio-dialog repair-dialog";
    dialog.setAttribute("aria-label", title);
    dialog.innerHTML = `<header class="repair-dialog-heading"><h2>${title}</h2>
      <button type="button" class="studio-close" aria-label="Закрыть">×</button></header>
      <form class="studio-dialog-form">${fields}<p class="repair-error" role="alert"></p>
        <div class="repair-actions"><button type="submit" class="button ${danger ? "danger" : "primary"}">${label}</button>
        <button type="button" class="button" data-repair-close>Отмена</button></div>
      </form>`;
    const form = dialog.querySelector("form");
    const close = dialog.querySelector(".studio-close");
    const cancel = dialog.querySelector("[data-repair-close]");
    const submit = form.querySelector('[type="submit"]');
    function removeDialog() {
      dialog.remove();
      if (modal !== dialog) return;
      modal = null;
      if (!life.signal.aborted && opener?.isConnected) opener.focus({preventScroll: true});
    }
    function dismiss() {
      dialog.close();
      removeDialog();
    }
    close.onclick = cancel.onclick = () => { if (!pending) dismiss(); };
    dialog.addEventListener("keydown", event => {
      if (event.key === "Escape") event.stopPropagation();
    });
    dialog.addEventListener("cancel", event => { if (pending) event.preventDefault(); });
    dialog.addEventListener("close", removeDialog, {once: true});
    form.onsubmit = async event => {
      event.preventDefault();
      if (pending || !writable()) return;
      const alert = form.querySelector("[role=alert]");
      alert.textContent = "";
      try {
        const payload = makePayload(new FormData(form));
        pending = true;
        readVersion++;
        clearTimeout(timer);
        close.disabled = cancel.disabled = submit.disabled = true;
        form.setAttribute("aria-busy", "true");
        await request(url, payload, {signal: life.signal});
        if (life.signal.aborted) return;
        dismiss();
        announce(success);
        selected.clear();
        refreshSelection();
      } catch (failure) {
        if (!life.signal.aborted) alert.textContent = failure.message;
      } finally {
        pending = false;
        close.disabled = cancel.disabled = submit.disabled = false;
        form.removeAttribute("aria-busy");
        load();
      }
    };
    host.append(dialog);
    dialog.showModal();
  }

  function modelSelect(session = null) {
    const models = (data.models || []).map(model => ({value: model.id, label: model.label || model.name || model.model || model.id}));
    const choices = [{value: "", label: defaultModelLabel}, ...models, {value: "@off", label: disabledModelLabel}];
    if (session) choices.unshift({value: "@keep", label: `Оставить предыдущий выбор · ${modelLabel(session.modelId)}`});
    return `<label class="field">Модель для оставшихся замечаний
      <select name="modelId">${optionRows(choices, session ? "@keep" : data.defaultModelId || "", e)}</select></label>`;
  }

  function showStart(ids, opener, detail) {
    if (!data?.available) return;
    const channels = (data.channels?.length ? data.channels : ["site"]).map(channel => typeof channel === "string"
      ? {value: channel, label: channelNames[channel] || channel}
      : {value: channel.id || channel.value, label: channel.label || channelNames[channel.id || channel.value]});
    const count = ids?.length ?? findings.length;
    showDialog("Начать исправление", opener, `
      <p>${detail ? e(detail) : `Выбрано замечаний · ${count}`}</p>
      <p>Если найдётся допустимая правка, «Штопка» создаст ветку и проверит изменения тем же сценарием.</p>
      ${modelSelect()}
      <small>Модель подключается, если для выбранных замечаний есть допустимые варианты исправления.</small>
      <label class="field">Куда прислать результат
        <select name="channel">${optionRows(channels, data.defaultChannel || "site", e)}</select></label>`,
    "Начать", form => ({
      action: "start", runId: report.id, findingIds: ids,
      modelId: form.get("modelId") || null, channel: form.get("channel") || "site",
    }), "Исправление поставлено в очередь.");
  }

  function showContinue(session, opener) {
    const rounds = session.rounds || [], latest = rounds.at(-1);
    const previous = rounds.slice(0, -1).reverse().find(round => round.runId && Array.isArray(round.remaining));
    const failed = latest?.status === "failed";
    const remaining = (latest?.remaining?.length ? latest.remaining : session.remaining || previous?.remaining || findings)
      .filter(finding => findingIdPattern.test(findingId(finding) || ""));
    if (!remaining.length && !failed) return;
    const retryIds = failed && new Set(latest.findingIds || []);
    showDialog(failed ? "Повторить исправление" : "Продолжить исправление", opener, `
      <p>Если найдётся правка, следующий раунд создаст новую ветку на основе предыдущих изменений.</p>
      ${remaining.length ? `<fieldset><legend>Оставшиеся замечания</legend><div class="repair-checklist">
        ${remaining.map(finding => `<label class="repair-choice"><input type="checkbox" name="findingId" value="${e(findingId(finding))}"
          ${!retryIds?.size || retryIds.has(findingId(finding)) ? "checked" : ""}>${e(findingLabel(finding))}</label>`).join("")}</div></fieldset>` : ""}
      ${modelSelect(session)}`,
    "Запустить раунд", form => {
      const ids = [...new Set(form.getAll("findingId"))];
      if (remaining.length && !ids.length) throw new Error("Выберите хотя бы одно замечание.");
      const model = form.get("modelId");
      return {action: "continue", sessionId: session.id, expectedRound: latest.number, findingIds: remaining.length ? ids : null,
        ...(model === "@keep" ? {} : {modelId: model || null})};
    }, "Следующий раунд поставлен в очередь.");
  }

  function showStop(session, opener) {
    const rounds = session.rounds || [], latest = rounds.at(-1);
    const branches = [...new Set(rounds.filter(round => round.commit && round.branchStatus !== "deleted" && round.branch)
      .map(round => round.branch))];
    showDialog("Остановить исправление", opener, `
      <p>Сеанс завершится. Выберите созданные в нём ветки, которые нужно удалить.</p>
      ${branches.length ? `<fieldset><legend>Удалить ветки</legend><div class="repair-checklist">
        ${branches.map(branch => `<label class="repair-choice"><input type="checkbox" name="branch" value="${e(branch)}"><code>${e(branch)}</code></label>`).join("")}</div></fieldset>` : ""}`,
    "Остановить сеанс", form => ({
      action: "stop", sessionId: session.id, expectedRound: latest.number, branches: form.getAll("branch"),
    }),
    "Остановка поставлена в очередь.", true);
  }

  panel.addEventListener("click", event => {
    const button = event.target.closest("[data-repair]");
    if (!button || !writable()) return;
    if (button.dataset.repair === "all") showStart(null, button);
    if (button.dataset.repair === "selected" && selected.size) showStart([...selected], button);
    const session = data?.sessions?.find(item => item.id === button.dataset.session);
    if (!session) return;
    if (button.dataset.repair === "continue" && session.canContinue) showContinue(session, button);
    if (button.dataset.repair === "stop" && session.canStop) showStop(session, button);
    if (button.dataset.repair === "accept" && session.canAccept) {
      showDialog("Подтвердить слияние", button,
        `<p>Проверенные изменения будут влиты в ${e(session.baseBranch || "основную ветку")}. Ветки этого сеанса будут удалены после слияния.</p>
         <label class="repair-choice"><input type="checkbox" required>Подтверждаю слияние</label>`,
        "Влить изменения", () => ({
          action: "accept", sessionId: session.id, expectedRound: session.rounds.at(-1).number,
        }), "Слияние поставлено в очередь.");
    }
  }, {signal: life.signal});
  load();
  return () => {
    life.abort();
    clearTimeout(timer);
    if (modal?.open) modal.close();
    for (const row of rowActions) row.controls.remove();
    panel.remove();
  };
}
