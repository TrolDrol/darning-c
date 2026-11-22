const events = {
  github_pr: "Pull request", github_push: "Push в GitHub", webhook: "HTTP-вебхук",
  schedule: "Расписание", manual: "Ручной запуск"
};
const weekdayNames = ["Пн","Вт","Ср","Чт","Пт","Сб","Вс"];
const localDate = new Intl.DateTimeFormat("ru-RU", {dateStyle:"short", timeStyle:"medium"});

export function scheduleTiming(schedule) {
  if (!schedule) return "";
  const zone = schedule.timezone || "UTC";
  if (schedule.cron) return `Cron ${schedule.cron} · ${zone}`;
  const days = schedule.weekdays ? schedule.weekdays.map(n => weekdayNames[n - 1]).join(", ") :
    schedule.monthDay ? `${schedule.monthDay}-го числа месяца` : "Ежедневно";
  return `${days} в ${schedule.time} · ${zone}`;
}

export function formatScheduleTime(at, zone) {
  if (!Number.isFinite(at)) return "";
  const options = {day:"numeric", month:"long", hour:"2-digit", minute:"2-digit", timeZone:zone || "UTC"};
  const date = new Date(at * 1000);
  if (!Number.isFinite(date.getTime())) return "";
  try {
    return new Intl.DateTimeFormat("ru-RU", options).format(date);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    return new Intl.DateTimeFormat("ru-RU", {...options, timeZone:"UTC"}).format(date) + " UTC";
  }
}

export function mountActivity(host, {request, url, escape:e, editorLink, back}) {
  host.innerHTML = `<section class="studio studio-activity"><header class="automation-header">
    <div><a href="${e(back)}">К редактору</a><h1>Активные сценарии</h1></div>
    <button type="button" class="button" data-activity-refresh>Обновить</button></header>
    <p data-activity-error role="alert"></p>
    <div data-activity-list><p>Загружаем состояние проекта…</p></div></section>`;
  const list = host.querySelector("[data-activity-list]");
  const refresh = host.querySelector("[data-activity-refresh]");
  const alert = host.querySelector("[data-activity-error]");
  let offset = 0, timer, loading = false, disposed = false, previousMarkup;
  function section(title, count, rows, empty) {
    return `<section class="studio-reports"><h2>${title} <small>${count}</small></h2>${rows.length ?
      `<ul class="activity-items">${rows.join("")}</ul>` : `<p>${empty}</p>`}</section>`;
  }
  async function load() {
    if (loading || disposed) return;
    clearTimeout(timer);
    loading = true;
    refresh.setAttribute("aria-busy","true");
    try {
      const data = await request(url + "&offset=" + offset);
      if (disposed) return;
      alert.textContent = "";
      const waiting = data.waiting.map(row => {
        const next = formatScheduleTime(row.schedule?.nextRunAt, row.schedule?.timezone);
        const timing = [events[row.trigger] || row.trigger, scheduleTiming(row.schedule), next && "Следующий запуск " + next].filter(Boolean);
        return `<li><div><a href="${e(editorLink(row.automationId))}">${e(row.automationName)}</a>
          <small>${e(timing.join(" · "))}</small></div></li>`;
      });
      const runs = data.runs.map(row => {
        const running = row.status === "running";
        const at = running ? row.startedAt : row.createdAt;
        const elapsed = at && Math.max(0, Math.floor((Date.now()/1000-at)/60));
        const since = at ? `${running?"Начат":"Поставлен в очередь"} ${localDate.format(new Date(at*1000))}${elapsed ? " · " + elapsed + " мин" : ""}` : "Время начала неизвестно";
        return `<li><div><a href="${e(editorLink(row.automationId,row.runId))}">${e(row.automationName)}</a>
          <small>${e(events[row.trigger] || row.trigger)} · ${e(since)}</small></div>
          <span class="chip">${row.status==="running"?"Выполняется":"В очереди"}</span></li>`;
      });
      const markup = section("В очереди и в работе",data.runsTotal,runs,"Сейчас нет запущенных проверок.") +
        section("Ожидают события или времени",data.waitingTotal,waiting,"На этой странице нет ожидающих сценариев.") +
        (offset || data.nextOffset != null ? `<div class="portal-actions">
          <button type="button" class="button" data-offset="${Math.max(0,offset-100)}" ${offset?"":"disabled"}>Назад</button>
          <button type="button" class="button" data-offset="${data.nextOffset ?? 0}" ${data.nextOffset==null?"disabled":""}>Дальше</button></div>` : "");
      if (markup !== previousMarkup) {
        const focus = list.contains(document.activeElement) ? document.activeElement : null;
        list.innerHTML = markup;
        if (focus) [...list.querySelectorAll("a,button")].find(el=>focus.href ? el.href===focus.href : el.textContent===focus.textContent)?.focus({preventScroll:true});
        previousMarkup = markup;
      }
    } catch (error) {
      if (!disposed) {
        alert.textContent = error.message;
        if (!previousMarkup) list.textContent = "";
      }
    } finally {
      loading = false;
      refresh.removeAttribute("aria-busy");
      if (!disposed) timer = setTimeout(load, 5000);
    }
  }
  refresh.onclick = load;
  list.onclick = event => {
    const button = event.target.closest("button[data-offset]");
    if (button && !loading) {offset = Number(button.dataset.offset); load();}
  };
  load();
  return () => {disposed = true; clearTimeout(timer);};
}
