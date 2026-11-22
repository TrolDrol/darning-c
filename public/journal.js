import {projectTabs} from "/project_hub.js";
import {personMarkup} from "/person.js";
import {midnight, dayString, readDate, presetRange} from "/date_range.js";
const periods = [["today", "Сегодня"], ["yesterday", "Вчера"], ["7", "7 дней"], ["14", "14 дней"], ["30", "30 дней"], ["90", "90 дней"]];
const categories = {all:"Все категории", runs:"Запуски", delivery:"Доставка", audit:"Действия"};
const columns = [["at", "Время"], ["category", "Категория"], ["event", "Событие"], ["actor", "Участник"], ["status", "Результат"], ["object", "Объект"]];
const calendarFormat = new Intl.DateTimeFormat("ru", {day:"numeric", month:"short", year:"numeric"});
const clockFormat = new Intl.DateTimeFormat("ru", {day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit"});

function rangeLabel({start, end}) {
  return calendarFormat.formatRange(start, end);
}

function calendarIcon() {
  return '<svg height="18" width="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><rect x="3.5" y="5.5" width="17" height="16" rx="3"/><path d="M8 3v5m8-5v5M4 11h16"/></svg>';
}

export function createJournal({page, request, getProjectId, getSettings, escape:e, announce}) {
  let container, scope, filters, pending, debounce, generation = 0;

  function leave() {
    generation++;
    clearTimeout(debounce);
    pending?.abort();
    container = null;
  }

  function range() {
    return filters.preset ? presetRange(filters.preset) : {start:readDate(filters.start), end:readDate(filters.end)};
  }

  function url(dates, pageNumber) {
    return "/api/journal?" + new URLSearchParams({
      project:scope, start:Math.floor(dates.start.getTime() / 1000), end:Math.floor(midnight(dates.end, 1).getTime() / 1000),
      category:filters.category, q:filters.q, sort:filters.sort, direction:filters.direction, page:pageNumber
    });
  }

  function rowMarkup(row, avatars) {
    const stamp = new Date(row.at * 1000);
    const id = encodeURIComponent(row.runId || "");
    const path = {graph:"#report/", run:"#runs/", delivery:"#outbox/", issue:"#issues/"}[row.target];
    const objectLabel = /^[a-f0-9]{32}$/.test(row.object) ? row.object.slice(0, 12) : row.object;
    const object = path ? `<a class="journal-object" href="${path}${id}" title="${e(row.object)}">${e(objectLabel)}</a>` : e(objectLabel);
    const settings = getSettings() || {};
    const configured = row.channel === "github" ? settings.githubConfigured : settings.smtpConfigured;
    const retry = row.category === "delivery" && row.target === "delivery" && ["github", "smtp"].includes(row.channel) &&
      settings.canWrite !== false && configured && (row.code === "temporary" || (!settings.asynchronous && row.code === "queued"));
    const tone = ["failed", "partial"].includes(row.code) ? "red" : ["review","temporary","unknown"].includes(row.code) ? "amber" : "";
    return `<tr><td><time datetime="${stamp.toISOString()}" title="${e(row.timeHint || "")}">${e(clockFormat.format(stamp))}</time></td>
      <td><span class="journal-category journal-category-${e(row.category)}">${e(categories[row.category])}</span></td>
      <td>${path ? `<a class="journal-event" href="${path}${id}">${e(row.event)}</a>` : e(row.event)}
        ${row.message ? `<small class="journal-message">${e(row.message)}</small>` : ""}</td>
      <td>${personMarkup(row.actorName || row.actor, avatars?.[row.actor])}</td><td>${row.status ? `<span class="chip ${tone}">${e(row.status)}</span>` : "—"}
        ${retry ? `<button type="button" class="link-button" data-j-retry="${e(row.runId)}" data-channel="${e(row.channel)}">${row.code === "queued" ? "Отправить" : "Повторить отправку"}</button>` : ""}</td>
      <td>${object || "—"}</td></tr>`;
  }

  function updateControls() {
    const dates = range();
    container.querySelector("[data-j-dates]").textContent = rangeLabel(dates);
    for (const [field, date] of Object.entries(dates)) container.querySelector(`[name="${field}"]`).value = dayString(date);
    container.querySelectorAll("[data-j-preset]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.jPreset === filters.preset)));
    container.querySelectorAll("[data-j-sort]").forEach(button => {
      const selected = button.dataset.jSort === filters.sort;
      button.closest("th").setAttribute("aria-sort", selected ? (filters.direction === "asc" ? "ascending" : "descending") : "none");
      button.querySelector("span").textContent = selected ? (filters.direction === "asc" ? "↑" : "↓") : "↕";
    });
    container.querySelector("[data-j-category]").value = filters.category;
  }

  async function load() {
    clearTimeout(debounce);
    const serial = ++generation;
    pending?.abort();
    pending = new AbortController();
    const results = container.querySelector("[data-j-results]");
    const summary = container.querySelector("[data-j-summary]");
    const nav = container.querySelector("[data-j-paging]");
    summary.textContent = "Загрузка событий…";
    results.setAttribute("aria-busy", "true");
    results.replaceChildren();
    nav.hidden = true;
    const dates = range();
    try {
      const data = await request(url(dates, filters.page), undefined, {signal:pending.signal});
      if (!container || serial !== generation) return;
      const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
      if (filters.page > pages) { filters.page = pages; await load(); return; }
      summary.textContent = data.total ? `Найдено событий · ${data.total.toLocaleString("ru")}` : "Событий за выбранный период и с этими фильтрами нет.";
      results.innerHTML = data.rows.map(row => rowMarkup(row, data.avatars)).join("");
      if (pages > 1) {
        nav.hidden = false;
        nav.querySelector("span").textContent = `Страница ${filters.page} из ${pages}`;
        nav.querySelector("[data-j-prev]").disabled = filters.page === 1;
        nav.querySelector("[data-j-next]").disabled = filters.page === pages;
      }
    } catch (error) {
      if (serial !== generation || !container || error.name === "AbortError") return;
      summary.textContent = error.message;
    } finally {
      if (serial === generation && container) {
        results.setAttribute("aria-busy", "false");
        page.setAttribute("aria-busy", "false");
      }
    }
  }

  async function open(category = "all") {
    leave();
    if (scope !== getProjectId() || !filters) {
      scope = getProjectId();
      filters = {preset:"7", category:"all", q:"", sort:"at", direction:"desc", page:1};
    }
    const selectedCategory = Object.hasOwn(categories, category) ? category : "all";
    if (filters.category !== selectedCategory) filters.page = 1;
    filters.category = selectedCategory;
    page.innerHTML = `<section class="journal">${projectTabs("journal",getProjectId())}<header class="portal-heading"><h1>Журнал</h1><div class="page-actions">
      <button class="button" data-j-reload type="button">Обновить</button>
      <a class="button" href="#scenarios/activity">Активные сценарии</a>
      ${getSettings()?.canWrite === false ? "" : '<a class="button primary" href="#scenarios/run">Запустить проверку</a>'}</div></header>
      <div class="journal-filters"><details class="journal-calendar"><summary>${calendarIcon()} <span data-j-dates></span> <span aria-hidden="true">⌄</span></summary>
        <form class="journal-calendar-form"><label class="field">С даты<input type="date" name="start" min="1970-01-01" max="9999-12-30" required></label>
        <label class="field">По дату<input type="date" name="end" min="1970-01-01" max="9999-12-30" required></label>
        <button class="button primary" type="submit">Применить</button></form></details>
        <div role="group" aria-label="Период" class="journal-periods">${periods.map(([key,label]) => `<button type="button" data-j-preset="${key}">${label}</button>`).join("")}</div></div>
      <div class="journal-list"><div class="journal-table-filters"><label class="journal-search"><span class="visually-hidden">Поиск по строкам журнала</span>
        <input type="search" maxlength="200" data-j-search placeholder="Найти событие, участника или объект" value="${e(filters.q)}"></label>
        <label><span class="visually-hidden">Категория</span><select data-j-category>${Object.entries(categories).map(([key,label]) => `<option value="${key}">${label}</option>`).join("")}</select></label></div>
        <div class="journal-counts" aria-live="polite" role="status"><span data-j-summary></span></div>
        <div class="journal-scroll" role="region" aria-label="События журнала" tabindex="0"><table><thead><tr>
        ${columns.map(([key,label]) => `<th scope="col"><button type="button" data-j-sort="${key}">${label} <span aria-hidden="true"></span></button></th>`).join("")}
        </tr></thead><tbody data-j-results></tbody></table></div>
        <nav class="journal-paging" data-j-paging aria-label="Страницы журнала" hidden><button type="button" class="button" data-j-prev>Назад</button><span></span>
        <button type="button" class="button" data-j-next>Далее</button></nav></div></section>`;
    container = page.querySelector(".journal");
    const dates = container.querySelector("details");
    const form = dates.querySelector("form");
    const search = container.querySelector("[data-j-search]");
    const refresh = () => { filters.page = 1; updateControls(); return load(); };
    form.addEventListener("submit", event => {
      event.preventDefault();
      if (form.end.value < form.start.value) {
        form.end.setCustomValidity("Выберите дату окончания после начала периода или в тот же день.");
        form.end.reportValidity();
        return;
      }
      Object.assign(filters, {preset:"", start:form.start.value, end:form.end.value});
      dates.open = false;
      dates.querySelector("summary").focus();
      refresh();
    });
    form.addEventListener("input", () => form.end.setCustomValidity(""));
    dates.addEventListener("keydown", event => {
      if (event.key === "Escape") { dates.open = false; dates.querySelector("summary").focus(); }
    });
    dates.addEventListener("toggle", () => { if (dates.open) updateControls(); });
    search.addEventListener("input", () => {
      filters.q = search.value;
      filters.page = 1;
      clearTimeout(debounce);
      debounce = setTimeout(load, 220);
    });
    container.querySelector("[data-j-category]").addEventListener("change", event => {
      filters.category = event.target.value;
      const hash = filters.category === "all" ? "#projects/journal" : "#projects/journal/" + filters.category;
      history.replaceState(history.state, "", hash);
      refresh();
    });
    container.addEventListener("click", async event => {
      const btn = event.target.closest("button");
      if (!dates.contains(event.target)) dates.open = false;
      if (!btn || btn.type === "submit") return;
      if (btn.hasAttribute("data-j-retry")) {
        btn.disabled = true;
        try {
          await request("/api/delivery/retry", {runId:btn.dataset.jRetry, channel:btn.dataset.channel});
          if (btn.isConnected) { announce("Состояние доставки обновлено"); await load(); }
        } catch (error) { if (btn.isConnected) { announce(error.message, true); btn.disabled = false; } }
        return;
      }
      if (btn.dataset.jPreset) filters.preset = btn.dataset.jPreset;
      else if (btn.dataset.jSort) {
        const next = btn.dataset.jSort;
        filters.direction = filters.sort === next ? (filters.direction === "desc" ? "asc" : "desc") : (next === "at" ? "desc" : "asc");
        filters.sort = next;
      } else if (btn.hasAttribute("data-j-prev") || btn.hasAttribute("data-j-next")) {
        filters.page += btn.hasAttribute("data-j-prev") ? -1 : 1;
        await load();
        return;
      } else if (!btn.hasAttribute("data-j-reload")) return;
      await refresh();
    });
    updateControls();
    await load();
  }
  return {open, leave};
}
