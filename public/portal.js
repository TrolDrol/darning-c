import {projectTabs} from "./project_hub.js";
import {personMarkup} from "/person.js";
import {midnight, dayString, readDate, presetRange} from "/date_range.js";

const titles = {
  analytics: "Аналитика", logs: "Журнал событий", profile: "Личный кабинет",
  projects: "Проекты", news: "Стена новостей"
};

const roles = {
  super_admin: "Супер-администратор", user: "Пользователь", owner: "Владелец предприятия", moderator: "Модератор",
  member: "Сотрудник", manager: "Руководитель проекта", editor: "Редактор", reader: "Читатель"
};

const ciScopes = {read: "Читать сценарии и результаты", run: "Запускать проверки",
  write: "Создавать и изменять сценарии", projects: "Создавать и переименовывать проекты"};

const statuses = {
  queued: ["В очереди", "neutral"], running: ["Идёт проверка", "amber"], review: ["С замечаниями", "amber"],
  passed: ["Пройдена", ""], partial: ["Проверена частично", "red"], skipped: ["Без анализа содержимого", "neutral"], failed: ["Сбой проверки", "red"]
};

const auditActions = {
  "ci.key.create": "Создан ключ CI/CD", "ci.key.revoke": "Отозван ключ CI/CD", "project.rename": "Проект переименован",
  save_draft: "Сохранён черновик", publish: "Опубликован сценарий", enqueue: "Поставлена в очередь проверка",
  "finding.triage": "Разобрано замечание", "smtp.retry": "Повторена отправка почты", "github.retry": "Повторена отправка в GitHub",
  "project.smtp.set": "Назначен получатель SMTP", "project.smtp.clear": "Снято назначение получателя SMTP",
  "organization.create": "Создано предприятие", "project.create": "Создан проект", "organization.member.set": "Назначена роль на предприятии",
  "organization.member.remove": "Удалён сотрудник", "project.member.set": "Назначена роль в проекте", "project.member.remove": "Удалён участник проекта",
  "invite.create": "Создано приглашение", "invite.revoke": "Отозвано приглашение", "invite.accept": "Принято приглашение",
  news_post_create: "Добавлена публикация", news_post_edit: "Изменена публикация", news_comment_create: "Добавлен комментарий",
  news_comment_edit: "Изменён комментарий", news_post_hide: "Скрыта публикация", news_comment_hide: "Скрыт комментарий"
};

const dateFormat = new Intl.DateTimeFormat("ru", {dateStyle: "medium", timeStyle: "short"});
const dayFormat = new Intl.DateTimeFormat("ru", {day: "numeric", month: "short", timeZone: "UTC"});
const periodFormat = new Intl.DateTimeFormat("ru", {day: "numeric", month: "short", year: "numeric"});
const numberFormat = new Intl.NumberFormat("ru");

const esc = value => String(value ?? "").replace(/[&<>"']/g, char => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char]
));
const encode = value => encodeURIComponent(value ?? "");
const number = value => numberFormat.format(Number(value) || 0);
const chip = (value, tone = "") => `<span class="chip ${tone}">${esc(value)}</span>`;
const role = value => roles[value] || value;
const roleChip = value => value ? chip(role(value)) : "";
const empty = value => `<p class="portal-empty">${esc(value)}</p>`;

function timestamp(value) {
  const date = value && new Date(value);
  return date && !Number.isNaN(date.valueOf())
    ? `<time datetime="${esc(date.toISOString())}">${esc(dateFormat.format(date))}</time>` : "—";
}

function endpoint(path, params = {}) {
  const url = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") url.set(key, value);
  }
  return url.size ? `/api/${path}?${url}` : `/api/${path}`;
}

function siteUrl(hash, project) {
  const url = new URL(location.pathname, location.origin);
  if (project) url.searchParams.set("project", project);
  url.hash = hash;
  return `${url}`;
}

function safeHref(value) {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : "";
  } catch {
    return "";
  }
}

function button(label, action, id = "", primary = false, compact = false) {
  return `<button type="button" class="${compact ? "link-button" : `button${primary ? " primary" : ""}`}"
    data-portal-action="${action}"${id === "" ? "" : ` data-record="${esc(id)}"`}>${esc(label)}</button>`;
}

function link(label, href, className = "link-button") {
  return `<a class="${className}" href="${esc(href)}">${esc(label)}</a>`;
}

function option(value, label, current) {
  return `<option value="${esc(value)}"${value === current ? " selected" : ""}>${esc(label)}</option>`;
}

function heading(view, caption = "", actions = "") {
  return `<header class="portal-heading"><div><h1>${titles[view]}</h1>${caption ? `<p>${esc(caption)}</p>` : ""}</div>
    ${actions ? `<div class="portal-actions portal-head-actions">${actions}</div>` : ""}</header>`;
}

function tile(title, body, actions = "") {
  return `<section class="portal-tile"><header class="portal-tile-head"><h2>${esc(title)}</h2>${actions}</header>${body}</section>`;
}

function table(headers, rows) {
  return `<div class="table-wrap" tabindex="0" role="region" aria-label="Таблица данных"><table class="portal-table">
    <thead><tr>${headers.map(header => `<th scope="col">${esc(header)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody>
    </table></div>`;
}

function organizationSelector(organizations, current, compact = false) {
  if (organizations.length === 1) return "";
  return `<label class="field portal-label-inline"><span${compact ? ' class="visually-hidden"' : ''}>Предприятие</span> <select data-portal-control="organization">
    ${compact ? '<button type="button"><selectedcontent></selectedcontent></button>' : ''}
    ${organizations.map(item => option(item.id, item.name, current)).join("")}</select></label>`;
}

function list(rows) {
  return `<ul class="portal-list">${rows.map(row => `<li>${row}</li>`).join("")}</ul>`;
}

function newsComment(comment) {
  const actions = [
    comment.canEdit ? button("Изменить", "edit-comment", comment.id, false, true) : "",
    comment.canHide ? button("Скрыть", "hide-comment", comment.id, false, true) : ""
  ].join("");
  return `<article class="portal-comment"><p class="portal-post-meta portal-muted">
    <strong>${esc(comment.author.displayName || comment.author.username)}</strong> ${timestamp(comment.createdAt)}
    ${comment.updatedAt ? "<span>Изменён</span>" : ""}</p><p>${esc(comment.body)}</p>
    ${actions ? `<div class="portal-actions">${actions}</div>` : ""}</article>`;
}

function newsPost(post, readOnly) {
  const url = safeHref(post.url);
  const source = post.source;
  const github = source?.publisher === "GitHub Advisory Database";
  const actions = [
    post.canEdit ? button("Изменить", "edit-post", post.id, false, true) : "",
    post.canHide ? button("Скрыть", "hide-post", post.id, false, true) : ""
  ].join("");
  return `<article class="portal-tile portal-post"><header class="portal-tile-head"><div>
    <h2>${esc(post.title)}</h2><p class="portal-post-meta portal-muted">
      ${chip(source ? (github ? "Бюллетень ИБ" : "Новости ИБ") : post.kind === "article" ? "Статья" : "Новость")}
      <strong>${esc(source ? source.publisher : post.author.displayName || post.author.username)}</strong>
      ${source && !github ? esc(source.byline) : ""} ${timestamp(source?.publishedAt || post.createdAt)}
      ${source && github && source.updatedAt !== source.publishedAt ? " · Обновлён " + timestamp(source.updatedAt) : ""}
      ${post.updatedAt ? "<span>Изменено</span>" : ""}</p></div>
    ${actions ? `<div class="portal-actions">${actions}</div>` : ""}</header>
    ${post.body ? `<p class="portal-post-body">${esc(post.body)}</p>` : ""}
    ${url ? `<a href="${esc(url)}" class="portal-post-link" target="_blank" rel="noopener noreferrer">${source ? "Первоисточник" : "Открыть статью"}</a>` : ""}
    ${source ? `<small class="portal-muted"> · Краткая карточка по материалам источника · <a href="https://creativecommons.org/licenses/by/${github ? "4.0" : "3.0"}/" target="_blank" rel="noopener noreferrer">CC BY ${github ? "4.0" : "3.0"}</a></small>` : ""}
    <section class="portal-comments" aria-label="Комментарии к записи">
      ${(post.comments || []).map(newsComment).join("")}
      <div class="portal-actions">
        ${readOnly ? "" : button("Комментировать", "new-comment", post.id)}
        ${post.commentCount > (post.comments?.length || 0) ? button(`Все комментарии (${number(post.commentCount)})`, "comments", post.id) : ""}
      </div>
    </section></article>`;
}


function metric(label, value) {
  return `<div class="portal-tile portal-metric"><dt>${esc(label)}</dt><dd>${number(value)}</dd></div>`;
}

function chart(rows) {
  const max = Math.max(1, ...rows.map(([, count]) => Number(count) || 0));
  return `<ul class="portal-chart">${rows.map(([label, count]) => `<li>
    <span>${esc(label)}</span><progress class="portal-chart-record" max="${max}" value="${Math.max(0, Number(count) || 0)}" aria-hidden="true"></progress>
    <strong class="portal-chart-value">${number(count)}</strong></li>`).join("")}</ul>`;
}

function dailyChart(timeline) {
  if (!timeline.length) return empty("В выбранном периоде нет запусков.");
  const max = Math.max(1, ...timeline.map(point => point.runs));
  return `<svg class="daily-bars" viewBox="0 0 ${timeline.length * 10} 100" preserveAspectRatio="none" role="img" aria-label="Количество запусков по дням">${timeline.map((point, i) => {
    const label = dayFormat.format(new Date(point.date));
    const height = 98 * point.runs / max;
    return `<g><title>${esc(label)} · запусков ${number(point.runs)}</title><rect x="${i*10}" width="10" height="100" fill="transparent"/><rect x="${i*10+1}" y="${100-height}" width="8" height="${height}" fill="currentColor"/></g>`;
  }).join("")}</svg><div class="daily-axis">${[0, Math.floor(timeline.length/2), timeline.length-1].map(i=>`<time>${esc(dayFormat.format(new Date(timeline[i].date)))}</time>`).join("")}</div>`;
}

function rosterTable(members, canEdit, scope) {
  if (!members.length) return empty(scope === "project" ? "Участники с назначенными ролями появятся здесь." : "Здесь появятся сотрудники предприятия.");
  const columns = ["Имя", "Роль"];
  if (canEdit) columns.push("Доступ");
  return table(columns, members.map(member => {
    const cells = [personMarkup(member.displayName || member.username, member.avatar)
      + (member.displayName && member.displayName !== member.username ? `<p class="portal-muted">${esc(member.username)}</p>` : ""), roleChip(member.role)];
    if (canEdit) cells.push(button("Изменить", `${scope}-member`, member.username, false, true));
    return cells;
  }));
}

export function createPortal({page, request, announce, getProjectId, getViewer = () => null, download}) {
  const dialog = document.createElement("dialog");
  dialog.className = "portal-dialog";
  dialog.setAttribute("aria-labelledby", "portal-dialog-title");
  document.body.append(dialog);

  let view;
  let project;
  let organization;
  let revision = 0;
  let state = {};
  let submitAction;
  let logType = "";
  let newsScope = "all";
  let newsPeriod = "all";
  let customNewsRange;
  let analyticsDays = 30;
  let thread;

  const scoped = (key, params = {}) => endpoint(key, {project, ...params});
  const isSuper = () => Boolean(getViewer()?.superAdmin || getViewer()?.role === "super_admin");

  function update(markup, busy = false) {
    page.innerHTML = `<div class="portal">${markup}</div>`;
    page.setAttribute("aria-busy", busy ? "true" : "false");
    const timeline = page.querySelector(".portal-day-plot");
    if (timeline) timeline.scrollLeft = timeline.scrollWidth;
  }

  function showDialog(title, body, submitLabel, onSubmit, focus = true) {
    submitAction = onSubmit;
    dialog.innerHTML = `<header class="portal-dialog-header"><h2 id="portal-dialog-title">${esc(title)}</h2>
      <button type="button" data-portal-close aria-label="Закрыть окно">×</button></header>
      <form><div class="dialog-body">${body}<p role="alert"></p></div>
      <footer class="dialog-footer"><button type="button" class="button" data-portal-close>${onSubmit ? "Отмена" : "Закрыть"}</button>
      ${onSubmit ? `<button type="submit" class="button primary">${esc(submitLabel)}</button>` : ""}</footer></form>`;
    if (!dialog.open) dialog.showModal();
    if (focus) dialog.querySelector("input:not([readonly]), textarea, select, [data-portal-close]").focus();
  }

  function showLink(title, caption, url) {
    showDialog(title, `<p class="portal-cap">${esc(caption)}</p><label class="field">Ссылка
      <input value="${esc(url)}" readonly data-portal-link></label>
      <div class="portal-actions">${button("Скопировать ссылку", "copy-link", "", true)}<span class="portal-muted" role="status"></span></div>`, null, null, false);
    const input = dialog.querySelector("[data-portal-link]");
    input.focus();
    input.select();
  }

  function share(projectId = getProjectId()) {
    if (projectId) showLink("Поделиться проектом", "Ссылка откроет проект для тех, у кого уже есть доступ.", siteUrl("projects", projectId));
  }

  function newsMarkup() {
    const {organizations, posts, nextCursor} = state;
    const customLabel = newsPeriod === "custom" ? periodFormat.formatRange(customNewsRange.start, customNewsRange.end) : "";
    const actions = organizations.length ? organizationSelector(organizations, organization, true) +
      `<label class="field"><span class="visually-hidden">Источник публикаций</span><select data-portal-control="news-scope">
        <button type="button"><selectedcontent></selectedcontent></button>
        ${option("all","Все публикации",newsScope)}${option("digest","Дайджест ИБ",newsScope)}${option("team","От сотрудников",newsScope)}</select></label>
       <label class="field"><span class="visually-hidden">Период публикации</span><select data-portal-control="news-period">
        <button type="button"><selectedcontent></selectedcontent></button>
        ${[["all","За всё время"],["today","Сегодня"],["yesterday","Вчера"],["7","За 7 дней"],["30","За 30 дней"],["90","За 90 дней"]].map(([key,label])=>option(key,label,newsPeriod)).join("")}
        ${customLabel ? option("custom",customLabel,newsPeriod) : ""}${option("choose","Указать даты…",newsPeriod)}</select></label>` +
      (getViewer()?.role === "reader" ? "" : button("Новая публикация", "new-post", "", true)) : "";
    return `${heading("news", "", actions)}
      <div class="portal-stack portal-feed">
        ${posts.length ? posts.map(p => newsPost(p, getViewer()?.role === "reader")).join("") : `<div class="portal-tile">${empty(organizations.length ? "По выбранным фильтрам публикаций нет." : "У вас пока нет доступа к стене предприятия.")}</div>`}
        ${nextCursor ? `<div>${button("Ещё публикации", "more-posts")}</div>` : ""}
      </div>`;
  }

  async function loadNews() {
    const [{organizations}, {projects}] = await Promise.all([request(endpoint("organizations")), request(endpoint("projects"))]);
    const selected = chooseOrganization(organizations, projects);
    const range = newsPeriod === "custom" ? customNewsRange : newsPeriod === "all" ? null : presetRange(newsPeriod);
    const query = {organization: selected, scope: newsScope,
      start:range?.start.toISOString(), end:range && midnight(range.end,1).toISOString()};
    const feed = selected ? await request(endpoint("news", query)) : {posts: []};
    return {organizations, selected, query, ...feed};
  }

  async function refreshNews(openThread) {
    await render("news");
    if (openThread && view === "news" && state.posts?.some(post => post.id === openThread)) await showThread(openThread);
  }

  function editPost(post) {
    const currentOrganization = organization;
    showDialog(post ? "Изменить публикацию" : "Новая публикация", `
      <label class="field">Вид публикации <select name="kind">${option("news", "Новость", post?.kind)}${option("article", "Статья", post?.kind)}</select></label>
      <label class="field">Заголовок <input required name="title" maxlength="120" value="${esc(post?.title)}"></label>
      <label class="field">Текст <textarea name="body" maxlength="5000">${esc(post?.body)}</textarea></label>
      <label class="field" data-portal-article${post?.kind === "article" ? "" : " hidden"}>Ссылка на статью
        <input name="url" type="url" maxlength="2048" value="${esc(post?.url)}"${post?.kind === "article" ? "" : " disabled"}></label>`,
    post ? "Сохранить" : "Опубликовать", async data => {
      const values = Object.fromEntries(data);
      if (!values.body.trim() && values.kind === "news") throw new Error("Введите текст новости.");
      await request(endpoint("news", {organization: currentOrganization}), {...values, id: post?.id});
      if (!post && newsScope === "digest") newsScope = "team";
      return () => refreshNews();
    });
    dialog.querySelector('[name="title"]').focus();
  }

  function editComment(postId, comment, reopen = false) {
    const currentOrganization = organization;
    showDialog(comment ? "Изменить комментарий" : "Новый комментарий", `
      <label class="field">Комментарий <textarea name="body" required maxlength="2000">${esc(comment?.body)}</textarea></label>`,
    comment ? "Сохранить" : "Отправить", async data => {
      await request(endpoint("news/comments", {organization: currentOrganization}), {id: comment?.id, postId, body: data.get("body")});
      return () => refreshNews(reopen ? postId : undefined);
    });
    dialog.querySelector("textarea").focus();
  }

  function hideNews(target, id, postId) {
    const currentOrganization = organization;
    const reopen = Boolean(dialog.open && thread?.postId === postId && target === "comment");
    const isPost = target === "post";
    showDialog(isPost ? "Скрыть публикацию?" : "Скрыть комментарий?",
      `<p>${isPost ? "Публикация и комментарии исчезнут со стены предприятия." : "Комментарий исчезнет из обсуждения."}</p>`,
      "Скрыть", async () => {
        await request(endpoint("news/moderate", {organization: currentOrganization}), {target, id});
        return () => refreshNews(reopen ? postId : undefined);
      });
  }

  async function showThread(postId, before) {
    const marker = revision;
    const {comments, nextCursor} = await request(endpoint("news", {organization, postId, before}));
    if (revision !== marker || view !== "news") return;
    thread = {postId, comments: before && thread?.postId === postId ? [...comments, ...thread.comments] : comments};
    const post = state.posts.find(item => item.id === postId);
    showDialog("Комментарии", `<div class="portal-stack portal-thread">
      ${post ? `<p><strong>${esc(post.title)}</strong></p>` : ""}
      ${nextCursor ? `<div>${button("Более ранние", "more-comments", nextCursor)}</div>` : ""}
      ${thread.comments.length ? thread.comments.map(newsComment).join("") : empty("Комментариев пока нет.")}
      ${getViewer()?.role === "reader" ? "" : `<div>${button("Комментировать", "new-comment", postId, true)}</div>`}</div>`);
  }

  function getComment(id) {
    return thread?.comments.find(comment => comment.id === id)
      || state.posts.flatMap(post => post.comments || []).find(comment => comment.id === id);
  }

  function chooseOrganization(organizations, projects = state.projects) {
    const candidates = [organization, projects?.find(item => item.id === project)?.organizationId, organizations[0]?.id];
    return candidates.find(id => organizations.some(item => item.id === id));
  }

  function exportLink(format, projectId, runId) {
    const href = endpoint("export", {project: projectId, runId, format});
    const fileType = {xlsx: "Excel (.xlsx)", "csv-ru": "CSV", json: "JSON"}[format];
    const label = fileType;
    return `<a class="button" href="${esc(href)}" download data-portal-download>${esc(label)}</a>`;
  }


  function analyticsMarkup() {
    if (!project) return missingProject("analytics");
    const {totals, statuses: counts, timeline} = state;
    const rows = Object.entries(counts).map(([key, value]) => [statuses[key]?.[0] || key, value]);
    const period = `<label class="field portal-label-inline"><span>Период</span><select data-portal-control="analytics-period">
      ${[7, 30, 90].map(days => option(days, `${days} дней`, analyticsDays)).join("")}</select></label>`;
    return `${projectTabs("analytics", project)}<section class="analytics-board" aria-label="Аналитика"><div class="analytics-tools">${period}
      <button type="button" class="button" popovertarget="analytics-export">Скачать ▾</button>
      <div id="analytics-export" popover>${exportLink("xlsx", project)}${exportLink("csv-ru", project)}</div></div>
      <dl class="portal-tiles">${metric("Запуски", totals.runs)}${metric("Пройдено", counts.passed)}
        ${metric("Всего проверок", totals.findings)}${metric("Уникальные ошибки", state.issues.open)}
        ${metric("Важные ошибки", state.issues.high)}</dl>
      <div class="portal-two-col">
        ${tile("Запуски по дням", dailyChart(totals.runs ? timeline : []))}
        ${tile("Результаты проверок", rows.length ? chart(rows) : empty("График появится после первого запуска."))}
      </div></section>`;
  }

  function missingProject(viewName) {
    return `${heading(viewName)}<div class="portal-tile">${empty("Выберите проект в разделе «Проекты».")}
      <div class="portal-actions">${link("К проектам", "#projects", "button")}</div></div>`;
  }

  function logsMarkup() {
    if (!project) return missingProject("logs");
    const events = state.events || [];
    const selectedActions = [...new Set(events.map(event => event.action))];
    const filtered = logType ? events.filter(event => event.action === logType) : events;
    const filter = selectedActions.length > 1 ? `<label class="field portal-label-inline">Действие
      <select data-portal-control="log-type">${option("", "Все действия", logType)}
      ${selectedActions.map(item => option(item, auditActions[item] || item, logType)).join("")}</select></label>` : "";
    return `${heading("logs", "История изменений и запусков выбранного проекта.", button("Обновить", "reload"))}
      ${tile("Действия в проекте", filtered.length ? table(["Время", "Действие", "Участник", "Объект"], filtered.map(event => [
        timestamp(event.createdAt), esc(auditActions[event.action] || event.action), esc(event.actor || "Система"), esc(event.subject || "—")
      ])) : empty("Событий пока нет."), filter)}`;
  }


  function projectMarkup() {
    const {organizations, chosenProject, organizationMembers, projectMembers, invitations} = state;
    const selected = organizations.find(item => item.id === organization);
    const canWrite = getViewer()?.role !== "reader";
    const canManageOrganization = canWrite && (isSuper() || selected?.role === "owner");
    const canManageProject = state.canManageProject;
    const organizationRoster = canManageOrganization && selected ? tile("Сотрудники предприятия",
      rosterTable(organizationMembers, true, "organization"), `<div class="portal-actions">
      ${button("Назначить роль", "organization-member")}${button("Пригласить", "organization-invite", "", true)}</div>`) : "";
    const projectRoster = chosenProject ? tile(chosenProject.name,
      rosterTable(projectMembers, canManageProject, "project"), canManageProject ? `<div class="portal-actions">
      ${button("Ключи CI/CD", "ci-keys")}${button("Получатель SMTP", "project-smtp")}${button("Добавить участника", "project-member")}${button("Пригласить", "project-invite", "", true)}</div>` : "") : "";
    const inviteTile = invitations.length ? tile("Действующие приглашения", list(invitations.map(invite => `
      <div><strong class="portal-card-name">${esc(invite.projectId ? chosenProject?.name : selected?.name)}</strong>
      ${roleChip(invite.projectRole || invite.organizationRole)}<p class="portal-muted">Действует до ${timestamp(invite.expiresAt)}</p></div>
      ${button("Отозвать", "revoke-invite", invite.id, false, true)}`))) : "";
    const controls = [selected ? organizationSelector(organizations, selected.id) : "",
      isSuper() ? button("Новое предприятие", "new-organization") : "",
      selected && canWrite ? button("Добавить проект", "new-project", "", true) : ""].join("");

    return `${projectTabs("projects", project)}
      ${controls ? `<div class="portal-actions">${controls}</div>` : ""}
      <div class="portal-stack project-rosters">${projectRoster}${organizationRoster}${inviteTile}</div>`;
  }

  async function loadProjects() {
    const [{organizations}, {projects}] = await Promise.all([request(endpoint("organizations")), request(endpoint("projects"))]);
    const selectedId = chooseOrganization(organizations, projects);
    const selected = organizations.find(item => item.id === selectedId);
    const chosenProject = projects.find(item => item.id === project);
    const defaultCollection = {members: [], invites: []};
    const canManageOrganization = selected && (isSuper() || selected.role === "owner");
    const [enterprise, team, enterpriseInvites, teamInvites] = await Promise.all([
      canManageOrganization ? request(endpoint("members", {organization: selectedId})) : defaultCollection,
      chosenProject ? request(endpoint("members", {project: chosenProject.id})) : defaultCollection,
      canManageOrganization ? request(endpoint("invitations", {organization: selectedId})) : defaultCollection,
      chosenProject?.role === "manager" && getViewer()?.role !== "reader" ? request(endpoint("invitations", {project: chosenProject.id})) : defaultCollection
    ]);
    return {organizations, projects, selected: selectedId, chosenProject, canManageProject:team.canManage, organizationMembers: enterprise.members,
      projectMembers: team.members, invitations: [...enterpriseInvites.invites, ...teamInvites.invites]};
  }

  async function ciKeys() {
    const selected = project;
    const marker = revision;
    const {keys, canCreateProjects} = await request(scoped("ci/keys"));
    if (marker !== revision) return;
    const availableProjects = state.projects.filter(p => p.organizationId === state.chosenProject.organizationId && p.role === "manager");
    const projectName = id => state.projects.find(p => p.id === id)?.name || id;
    showDialog("Ключи CI/CD", `${keys.length ? list(keys.map(k => `<div><strong>${esc(k.label)}</strong>
      <p>${esc(k.scopes.map(s => ciScopes[s]).join(" · "))}</p>
      <p class="portal-muted">${esc(k.projects.map(projectName).join(", "))}</p></div>
      ${button("Отозвать", "ci-revoke", k.id, false, true)}`)) : empty("Действующих ключей пока нет.")}
      <h3>Новый ключ</h3><label class="field">Название<input name="name" maxlength="100" required placeholder="Например, сборка релиза"></label>
      <fieldset><legend>Права</legend>${Object.entries(ciScopes).filter(([s]) => s !== "projects" || canCreateProjects)
        .map(([s, text]) => `<label><input type="checkbox" name="scope" value="${s}" ${s === "read" ? "checked" : ""}> ${text}</label><br>`).join("")}</fieldset>
      <fieldset><legend>Доступные проекты</legend>${availableProjects.map(p =>
        `<label><input type="checkbox" name="projects" value="${esc(p.id)}" ${p.id === selected ? "checked disabled" : ""}> ${esc(p.name)}</label><br>`).join("")}</fieldset>`,
      "Создать ключ", async data => {
        const {token} = await request(endpoint("ci/keys", {project: selected}), {action: "create", name: data.get("name"),
          scopes: data.getAll("scope"), projects: [selected, ...data.getAll("projects")]});
        return () => {
          showDialog("Ключ CI/CD создан", `<p>Сохраните ключ в секретах CI. Значение показывается один раз.</p>
            <label class="field">Bearer-ключ<input readonly data-ci-secret value="${esc(token)}"></label>`, null, null, false);
          const field = dialog.querySelector("[data-ci-secret]");
          field.focus();
          field.select();
        };
      });
  }

  function revokeCiKey(id) {
    const selected = project;
    showDialog("Отозвать ключ CI/CD?", "<p>Новые запросы с этим ключом перестанут приниматься.</p>", "Отозвать", async () => {
      await request(endpoint("ci/keys", {project: selected}), {action: "revoke", id});
      return ciKeys;
    });
  }

  async function smtpRecipient() {
    const selected = project;
    const marker = revision;
    const url = endpoint("project/smtp", {project: selected});
    const {configured, managedByOperator, own, verifiedEmail} = await request(url);
    if (marker !== revision) return;
    if (managedByOperator) {
      showDialog("Получатель SMTP", "<p>Оператор назначил общий адрес проекта. На него приходят сводки ручных и автоматических запусков.</p>");
      return;
    }
    const canSet = Boolean(verifiedEmail && (!own || !configured));
    let status = "Получатель проекта пока не назначен или недоступен.";
    if (configured) status = own
      ? `Назначен ваш подтверждённый адрес <strong>${esc(verifiedEmail)}</strong>.`
      : "Назначен подтверждённый адрес другого руководителя.";
    const help = canSet
      ? `<p>${configured ? "Заменить текущего получателя вашим подтверждённым адресом" : "Назначить ваш подтверждённый адрес"} <strong>${esc(verifiedEmail)}</strong>?</p>`
      : verifiedEmail ? "" : "<p>Подтвердите адрес в меню профиля → «Привязка почты».</p>";
    const clear = configured || own ? `<div class="portal-actions">${button("Снять назначение", "project-smtp-clear")}</div>` : "";
    showDialog("Получатель SMTP", `<p>${status}</p>
      <p>Настройка действует для автоматических запусков проекта. Письмо содержит число замечаний и ссылку на отчёт.</p>
      ${help}${clear}`,
      "Назначить свою почту", canSet ? async () => {
        await request(url, {action: "set"});
        return () => announce("Получатель SMTP проекта сохранён.");
      } : null);
  }

  function clearSmtpRecipient() {
    const selected = project;
    showDialog("Снять назначение получателя SMTP?",
      "<p>Сводки автоматических запусков по почте возобновятся после назначения получателя.</p>", "Снять назначение", async () => {
      await request(endpoint("project/smtp", {project: selected}), {action: "clear"});
      return () => announce("Назначение получателя SMTP снято.");
    });
  }

  function changeMember(scope, username) {
    const selected = organization;
    const chosen = state.chosenProject?.id;
    const inProject = scope === "project";
    const row = (inProject ? state.projectMembers : state.organizationMembers).find(item => item.username === username);
    const assignable = inProject ? ["reader", "editor", "manager"] : ["member", "moderator", "owner"];
    const params = inProject ? {project: chosen} : {organization: selected};
    const label = row ? "Изменить роль" : inProject ? "Добавить участника" : "Назначить роль на предприятии";
    showDialog(label, `
      ${row ? `<p><strong>${esc(row.displayName || row.username)}</strong> <span class="portal-muted">${esc(row.username)}</span></p>` :
    `<label class="field">Логин сотрудника <input name="username" required maxlength="64" autocomplete="off"></label>`}
      <label class="field">Роль <select name="role" required>${assignable.map(key => option(key, role(key), row?.role)).join("")}
      ${row ? option("remove", "Отозвать доступ", row.role) : ""}</select></label>
      ${inProject ? `<p class="portal-muted">Читатель видит отчёты. Редактор меняет сценарии и запускает проверки. Руководитель управляет доступом.</p>` : ""}`,
    "Сохранить", async data => {
      const selectedRole = data.get("role");
      await request(endpoint("members", params), {username: row?.username || data.get("username").trim(), role: selectedRole === "remove" ? null : selectedRole});
      return () => render("projects");
    });
  }

  function inviteMember(scope) {
    const inProject = scope === "project";
    const organizationId = organization;
    const projectId = inProject ? state.chosenProject?.id : undefined;
    const assignable = inProject ? ["reader", "editor", "manager"] : ["member", "moderator"];
    showDialog(inProject ? "Пригласить в проект" : "Пригласить на предприятие", `
      <p>Создайте одноразовую ссылку и передайте её сотруднику.</p>
      <label class="field">Роль <select name="role">${assignable.map(key => option(key, role(key))).join("")}</select></label>
      ${inProject ? `<p class="portal-muted">Читатель видит отчёты. Редактор меняет сценарии и запускает проверки. Руководитель управляет доступом.</p>` : ""}`,
    "Создать приглашение", async data => {
      const selectedRole = data.get("role");
      const result = await request(endpoint("invitations", projectId ? {project: projectId} : {organization: organizationId}), {role: selectedRole});
      return async () => {
        showLink("Приглашение готово", "Передайте одноразовую ссылку сотруднику. Она действует до указанной даты.",
          result.url);
        const date = document.createElement("p");
        date.className = "portal-muted";
        date.innerHTML = `Действует до ${timestamp(result.invite.expiresAt)}`;
        dialog.querySelector(".dialog-body").prepend(date);
        await render("projects", true);
      };
    });
  }

  function createSpace(kind) {
    const enterprise = kind === "organizations";
    const organizationId = organization;
    showDialog(enterprise ? "Новое предприятие" : "Новый проект", `
      <label class="field">Название <input name="name" required maxlength="120"></label>`, "Создать", async data => {
      const result = await request(endpoint(kind), {name: data.get("name").trim(), organizationId: enterprise ? undefined : organizationId});
      return async () => {
        if (enterprise) organization = result.organization?.id || result.id;
        else { location.assign(siteUrl("projects", result.project.id)); return; }
        await render("projects");
      };
    });
  }

  function revokeInvite(id) {
    const invite = state.invitations.find(item => item.id === id);
    if (!invite) return;
    showDialog("Отозвать приглашение?", `<p>Ссылка перестанет открывать доступ.</p>`, "Отозвать", async () => {
      await request(endpoint("invitations", invite.projectId ? {project: invite.projectId} : {organization: invite.organizationId}), {revokeId: id});
      return () => render("projects");
    });
  }

  const loaders = {
    analytics: () => project ? request(scoped("analytics", {days: analyticsDays})) : {},
    logs: () => project ? request(scoped("logs")) : {},
    projects: loadProjects, news: loadNews
  };
  const screens = {analytics: analyticsMarkup, logs: logsMarkup, projects: projectMarkup, news: newsMarkup};

  async function render(next, keepDialog = false) {
    const nextProject = getProjectId();
    if (project !== nextProject || view !== next) {
      organization = undefined;
      logType = "";
    }
    project = nextProject;
    view = next;
    thread = undefined;
    const marker = ++revision;
    if (!keepDialog && dialog.open) dialog.close();
    update('<p class="portal-empty" role="status">Загрузка…</p>', true);
    try {
      const result = await loaders[next]();
      if (marker !== revision) return;
      if (result.selected) organization = result.selected;
      state = result;
      if (next === "logs" && !state.events?.some(event => event.action === logType)) logType = "";
      update(screens[next]());
    } catch (error) {
      if (marker !== revision) return;
      state = {};
      update(`${heading(next)}<div class="portal-tile"><p class="portal-empty" role="alert">${esc(error.message || "Раздел временно недоступен.")}</p>
        <div>${button("Повторить", "reload")}</div></div>`);
    }
  }

  function leave() {
    view = undefined;
    state = {};
    revision += 1;
    if (dialog.open) dialog.close();
  }

  async function morePosts(control) {
    const marker = revision;
    control.disabled = true;
    try {
      const {posts, nextCursor} = await request(endpoint("news", {...state.query, before: state.nextCursor}));
      if (marker !== revision) return;
      const existing = new Set(state.posts.map(post => post.id));
      const firstNew = state.posts.length;
      state = {...state, posts: [...state.posts, ...posts.filter(post => !existing.has(post.id))], nextCursor};
      update(newsMarkup());
      const target = page.querySelectorAll(".portal-post h2")[firstNew];
      if (target) {
        target.tabIndex = -1;
        target.focus();
      }
    } finally {
      control.disabled = false;
    }
  }

  const actions = {
    reload: () => render(view),
    "share-project": share,
    "new-organization": () => createSpace("organizations"),
    "new-project": () => createSpace("projects"),
    "organization-member": id => changeMember("organization", id),
    "project-member": id => changeMember("project", id),
    "ci-keys": ciKeys,
    "ci-revoke": revokeCiKey,
    "project-smtp": smtpRecipient,
    "project-smtp-clear": clearSmtpRecipient,
    "organization-invite": () => inviteMember("organization"),
    "project-invite": () => inviteMember("project"),
    "revoke-invite": revokeInvite,
    "export-run": id => {
      const run = state.runs.find(item => item.id === id);
      if (!run) return;
      showDialog("Скачать отчёт", `<p>Выберите формат результатов проверки.</p>
        <div class="portal-actions">${["xlsx", "csv-ru", "json"].map(format => exportLink(format, run.projectId || project, id)).join("")}</div>`);
    },
    "new-post": () => editPost(),
    "edit-post": id => editPost(state.posts.find(post => post.id === id)),
    "hide-post": id => hideNews("post", id),
    "new-comment": id => editComment(id, undefined, thread?.postId === id && dialog.open),
    "edit-comment": id => {
      const comment = getComment(id);
      if (comment) editComment(comment.postId, comment, Boolean(thread && dialog.open));
    },
    "hide-comment": id => {
      const comment = getComment(id);
      if (comment) hideNews("comment", id, comment.postId);
    },
    comments: id => showThread(id),
    "more-comments": id => showThread(thread?.postId, id),
    "more-posts": (_id, control) => morePosts(control),
    "copy-link": async () => {
      const input = dialog.querySelector("[data-portal-link]");
      const error = dialog.querySelector('[role="alert"]');
      try {
        await navigator.clipboard.writeText(input.value);
        error.textContent = "";
        dialog.querySelector('[role="status"]').textContent = "Ссылка скопирована.";
      } catch {
        input.focus();
        input.select();
        error.textContent = "Скопируйте выделенную ссылку вручную.";
      }
    }
  };

  async function click(event) {
    const action = event.target.closest("[data-portal-action]");
    const file = event.target.closest("[data-portal-download]");
    if (file && download) event.preventDefault();
    try {
      if (action) await actions[action.dataset.portalAction](action.dataset.record, action);
      if (file && download) {
        file.closest("[popover]")?.hidePopover();
        await download(file.getAttribute("href"));
      }
    } catch (error) {
      if (dialog.open) dialog.querySelector('[role="alert"]').textContent = error.message;
      else announce(error.message, true);
    }
  }

  page.addEventListener("click", click);
  page.addEventListener("change", async ({target}) => {
    const control = target.dataset.portalControl;
    if (control === "organization") {
      organization = target.value;
      await render(view);
      page.querySelector('[data-portal-control="organization"]')?.focus();
    } else if (control === "log-type") {
      logType = target.value;
      update(logsMarkup());
      page.querySelector('[data-portal-control="log-type"]')?.focus();
    } else if (control === "news-period" && target.value === "choose") {
      target.value = newsPeriod;
      const current = newsPeriod === "custom" ? customNewsRange : presetRange(newsPeriod === "all" ? "7" : newsPeriod);
      showDialog("Даты публикации", `<label class="field">С<input type="date" name="start" required value="${dayString(current.start)}"></label>
        <label class="field">По включительно<input type="date" name="end" required value="${dayString(current.end)}"></label>`, "Применить", data => {
        const start = readDate(data.get("start")), end = readDate(data.get("end"));
        if (start > end) throw new Error("Начальная дата должна быть раньше конечной или совпадать с ней.");
        newsPeriod = "custom";
        customNewsRange = {start, end};
        return () => refreshNews();
      });
    } else if (control === "news-scope" || control === "news-period") {
      if (control === "news-scope") newsScope = target.value;
      else newsPeriod = target.value;
      await render("news");
      page.querySelector(`[data-portal-control="${control}"]`)?.focus();
    } else if (control === "analytics-period") {
      analyticsDays = Number(target.value);
      await render("analytics");
      page.querySelector('[data-portal-control="analytics-period"]')?.focus();
    }
  });

  dialog.addEventListener("click", event => {
    if (event.target.closest("[data-portal-close]")) dialog.close();
    else click(event);
  });

  dialog.addEventListener("change", ({target}) => {
    if (target.name !== "kind") return;
    const field = dialog.querySelector("[data-portal-article]");
    field.hidden = target.value !== "article";
    field.querySelector("input").disabled = field.hidden;
  });

  dialog.addEventListener("submit", async event => {
    event.preventDefault();
    if (!submitAction || event.target.dataset.busy) return;
    const form = event.target;
    const marker = revision;
    const error = form.querySelector('[role="alert"]');
    error.textContent = "";
    const data = new FormData(form);
    form.dataset.busy = "true";
    const controls = Array.from(form.elements).filter(control => !control.disabled);
    const closeButton = dialog.querySelector(".portal-dialog-header button");
    controls.forEach(control => { control.disabled = true; });
    closeButton.disabled = true;
    try {
      const after = await submitAction(data);
      if (marker !== revision) return;
      dialog.close();
      await after?.();
    } catch (failure) {
      if (dialog.open && form.isConnected) error.textContent = failure.message;
      else announce(failure.message, true);
    } finally {
      delete form.dataset.busy;
      controls.forEach(control => { control.disabled = false; });
      closeButton.disabled = false;
    }
  });

  dialog.addEventListener("cancel", event => {
    if (dialog.querySelector("form[data-busy]")) event.preventDefault();
  });
  dialog.addEventListener("close", () => {
    if (!dialog.open && dialog.querySelector("[data-ci-secret]")) dialog.replaceChildren();
  });

  return {render, leave, share};
}
