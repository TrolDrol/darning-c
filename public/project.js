import {repositoryName} from "/source_picker.js";
import {connectionsOf, pendingsOf, openRepositorySetup} from "/repository_setup.js";
import {projectRoute, projectTabs} from "/project_hub.js";

export function createProjectScreens({page, request, getProjectId, announce, escape, canWrite}) {
  let revision = 0;
  let active;
  let detailId;
  let filter = "open";
  let issueRepository = "";
  let allProjects = false;
  let issueId;
  let offset = 0;
  let repositoryData;
  let wizard;
  const filters = {open:"Открытые", new:"Новые", mine:"Мои", high:"Высокая важность", review:"Пора пересмотреть", fixed:"Исправленные", all:"Все"};
  const decisions = {open:"На рассмотрении", accepted:"Риск принят", false_positive:"Ложное срабатывание"};
  const dates = new Intl.DateTimeFormat("ru", {dateStyle:"short",timeStyle:"short"});
  const when = value => value ? escape(dates.format(new Date(value))) : "—";
  const link = (url, label, primary=false) => `<a class="button${primary ? " primary" : ""}" href="${escape(url)}">${escape(label)}</a>`;
  const option = (key, label, selected) => `<option value="${escape(key)}" ${key === selected ? "selected" : ""}>${escape(label)}</option>`;
  const tile = (title, body) => `<section class="portal-tile"><h2>${escape(title)}</h2>${body}</section>`;
  const actions = content => `<div class="portal-actions">${content}</div>`;
  function api(name, params={}) {
    const query = new URLSearchParams(params);
    if (getProjectId()) query.set("project", getProjectId());
    return `/api/${name}?${query}`;
  }
  const issueScope = () => ({scope:allProjects ? "all" : "", repository:issueRepository});
  function issueLink(i, scoped=false) {
    const hash = projectRoute("issues", i.id, scoped ? {...issueScope(), filter} : {});
    if (!i.projectId || i.projectId === getProjectId()) return hash;
    const url = new URL(location.pathname, location.origin);
    url.searchParams.set("project", i.projectId);
    url.hash = hash;
    return url.href;
  }
  const issueLocation = issue => escape(issue.file) + (issue.line ? ":" + escape(issue.line) : "");
  const issueSummary = issue => `<strong>${escape(issue.title)}</strong><small>${escape(issue.ruleId)} · ${issueLocation(issue)} · ${issue.level === "high" ? "Высокая" : "Средняя"} · ${escape(issue.assignee || "Без ответственного")}</small>`;
  function overview() {
    const destinations = [
      ["#projects", "К проектам", '<path d="M3 8V5h6l2 3h10v11H3z"/>'],
      ["#projects/issues", "К замечаниям", '<path d="M6 3h12v18H6zM9 8h6M9 12h6M9 16h4"/>'],
      ["#analytics", "К аналитике", '<path d="M4 3v17h17M8 15v-4m5 4V6m5 9V9"/>']
    ];
    return `<nav class="overview-destinations" aria-label="Обзор проекта">${destinations.map(([url,label,icon]) =>
      `<a href="${url}"><svg class="overview-icon" viewBox="0 0 24 24" aria-hidden="true">${icon}</svg><span>${label}</span>
       <svg class="overview-arrow" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h13m-5-5 5 5-5 5"/></svg></a>`).join("")}</nav>`;
  }
  function issueList(data, repositories) {
    const more = offset + data.issues.length < data.total;
    const source = allProjects ? "all" : issueRepository || "project";
    const sources = [option("all","Все доступные проекты",source)];
    if (getProjectId()) sources.push(option("project","Текущий проект целиком",source));
    for (const name of repositories) sources.push(option(name,name,source));
    return `<header class="portal-heading"><div><h1>Замечания</h1><p>Найдено ${escape(data.total)}</p></div></header>
      <div class="project-filters"><label class="field">Область<select data-issue-scope>${sources.join("")}</select></label>
      <label class="field">Показать<select data-issue-filter>${Object.entries(filters).map(([key,label])=>option(key,label,filter)).join("")}</select></label></div>
      ${tile(filters[filter], data.issues.length ? `<ul class="issue-list">${data.issues.map(i=>`<li><a href="${escape(issueLink(i,true))}">${issueSummary(i)}<small>${escape([data.projectNames?.[i.projectId], i.repository].filter(Boolean).join(" · "))}</small></a></li>`).join("")}</ul>` : "<p>По этому фильтру замечаний нет.</p>")}
      ${actions((offset ? '<button class="button" data-offset="back">Назад</button>' : "") + (more ? '<button class="button" data-offset="next">Далее</button>' : ""))}`;
  }
  function issueCard({issue:i,candidates,canWrite:editable}) {
    const f = i.finding || {};
    const labels = {assigned:"Назначение",seen:"Обнаружено",fixed:"Исправлено",reopened:"Открыто повторно",triage:"Решение",created:"Обнаружено",observed:"Обнаружено",assignment:"Назначение",detected:"Обнаружено"};
    const history = (i.history || []).map(h => {
      const data = h.details || {};
      const change = h.action === "assigned" ? data.assignee || "Без ответственного" :
        [decisions[data.status], data.decision?.reason, data.decision?.expiresAt].filter(Boolean).join(" · ");
      return `<li>${when(h.createdAt)} · ${escape(labels[h.action] || h.action)} ${escape(change)} ${escape(h.actor || "")}
        ${h.runId ? `<a href="#runs/${encodeURIComponent(h.runId)}">Отчёт</a>` : ""}</li>`;
    }).join("");
    const form = editable ? `<details class="issue-edit"><summary>Изменить назначение или решение</summary><form data-project-form="issue">
      <label class="field">Ответственный<select name="assignee">${option("","Без ответственного",i.assignee || "")}${candidates.map(c=>option(c.username,c.displayName || c.username,i.assignee)).join("")}</select></label>
      <label class="field">Решение<select name="status">${Object.entries(decisions).map(([k,v])=>option(k,v,i.triage)).join("")}</select></label>
      <label class="field">Причина решения<input name="reason" maxlength="300" value="${escape(i.triageDecision?.reason || "")}"></label>
      <label class="field">Дата пересмотра<input type="date" name="expiresAt" value="${escape(i.triageDecision?.expiresAt || "")}"></label>
      <button class="button primary">Сохранить</button><p role="alert"></p></form></details>` : "";
    return `<header class="portal-heading"><div><a href="${escape(projectRoute("issues",filter,issueScope()))}">К списку замечаний</a><h1>${escape(i.title)}</h1><p>${escape(i.ruleId)} · ${issueLocation(i)}</p></div></header>
      <div class="portal-two-col"><div class="portal-stack">${tile("Доказательство",`<pre>${escape(f.evidence || "")}</pre><p>${escape(f.risk || "")}</p>`)}
      ${tile("Исправление и проверка", i.finding ? `<p>${escape(f.recommendation?.action || f.fix || "")}</p><p>${escape(f.verify || "")}</p>${actions(link("#runs/"+i.lastRunId,"Открыть проверку"))}` : "<p>Срок хранения исходного отчёта истёк. История замечания доступна в карточке.</p>")}</div>
      <div class="portal-stack">${tile("Состояние",`<p>${i.state === "fixed" ? "Исправлено" : "Открыто"} · ${escape(decisions[i.triage] || "")}</p><p>Ответственный — ${escape(i.assignee || "не назначен")}</p>${i.triageDecision ? `<p>${escape(i.triageDecision.reason)} · пересмотр ${escape(i.triageDecision.expiresAt)}</p>` : ""}${form}`)}
      ${tile("История",`<ul>${history}</ul>`)}</div></div>`;
  }
  function connectionCard(c, canManage) {
    const binding = `<input type="hidden" name="bindingId" value="${escape(c.bindingId)}">`;
    const form = fields => `<form data-project-form="repository">${binding}${fields}<p role="alert"></p></form>`;
    const scope = `<p>Имена файлов — ${c.pythonPath || c.configPath ? "в пределах фильтров" : "по всему снимку"}<br>Python — ${c.pythonPath ? escape(c.pythonPath) : "все файлы .py"}<br>
      JSON — ${c.configPath ? escape(c.configPath) : "все файлы .json"}</p>`;
    const edit = `<details class="issue-edit"><summary>Изменить выбор файлов</summary>${form(
      `<p>Оставьте поля пустыми для поиска во вложенных папках или укажите путь от корня репозитория.</p>
      <label class="field">Один файл Python · необязательно<input name="pythonPath" placeholder="src/calculator.py" value="${escape(c.pythonPath || "")}"></label>
      <label class="field">Один файл JSON · необязательно<input name="configPath" placeholder="config/settings.json" value="${escape(c.configPath || "")}"></label>
      <button class="button" name="action" value="scope">Сохранить выбор файлов</button>`)}
      </details>`;
    const clear = (c.pythonPath || c.configPath) ? form(`<input type="hidden" name="pythonPath" value=""><input type="hidden" name="configPath" value="">
      <button class="button" name="action" value="scope" data-all-files>Проверять все файлы Python и JSON</button>`) : "";
    const manage = form(`<div class="portal-actions"><button class="button primary" name="action" value="test">Пробная проверка</button>
      <button class="button" name="action" value="disconnect">Отключить</button></div>`);
    const start = "#scenarios/run?" + new URLSearchParams({repository:c.repository, binding:"@bound:" + c.bindingId});
    const links = actions((canWrite() ? link(start, "Проверить по сценарию", true) : "") + link(projectRoute("issues","",{repository:c.repository}),"Замечания репозитория") +
      link(projectRoute("releases","",{repository:c.repository}),"Сравнить релизы"));
    return `<article class="portal-tile repo-card" data-repo-card="${escape(c.repository)}"><h2>${escape(c.repository)}</h2>
      ${links}${scope}${canManage ? clear + edit + manage : ""}</article>`;
  }
  function repository(data) {
    const connections = connectionsOf(data);
    const pendings = data.canManage ? pendingsOf(data) : [];
    const prSettings = data.canManage && connections.length ? tile("Проверки pull request",
      `<form data-project-form="repository"><p>Для подключённых репозиториев проекта проверки GitHub ${data.checkPullRequests ? "включены" : "выключены"}.</p>
      <input type="hidden" name="enabled" value="${!data.checkPullRequests}">
      <button class="button" name="action" value="pull_requests">${data.checkPullRequests ? "Выключить" : "Включить"} проверки</button><p role="alert"></p></form>`) : "";
    const add = data.canManage && data.configured ? '<button type="button" class="button primary" data-repo-add>Добавить репозиторий</button>' : "";
    const requests = pendings.map(p => `<article class="portal-tile repo-card" data-repo-card="${escape(p.repository)}">
      <h2>${escape(p.repository)}</h2><p>Ожидаем коммит с подтверждением до ${when(p.expiresAt)}.</p>
      <form data-project-form="repository"><input type="hidden" name="repository" value="${escape(p.repository)}">
        <div class="portal-actions"><button type="button" class="button" data-repo-resume="${escape(p.repository)}">Продолжить подключение</button>
        <button class="button" name="action" value="cancel">Отменить запрос</button></div><p role="alert"></p></form></article>`).join("");
    const help = data.configured ? '<p>Сценарий определяет состав репозитория и применяет включённые правила к подходящим файлам. Подробности об охвате доступны в отчёте проверки.</p><p><a href="#scenarios">Сценарии проекта</a></p>' :
      '<p>Администратору стенда нужно настроить GitHub App и подписки на события Push и Pull request.</p>';
    return `<header class="portal-heading"><div><h1>Репозитории</h1><p>Источники файлов для проверок этого проекта.</p></div>
      ${actions(add + '<button class="button" data-project-refresh>Обновить</button>')}</header>
      <div class="portal-two-col"><div class="portal-stack">${connections.map(c=>connectionCard(c,data.canManage)).join("")}${requests}
      ${connections.length || pendings.length ? "" : tile("Подключённые репозитории", "<p>У проекта пока нет подключённых репозиториев.</p>")}</div>
      <div class="portal-stack">${prSettings}${tile("Какие файлы проверяются",help + (data.canManage ? "" : "<p>Репозитории подключает руководитель проекта.</p>"))}</div></div>`;
  }
  function showRepositories(data) {
    repositoryData = data;
    page.innerHTML = `<div class="portal project-screen">${projectTabs("repository",getProjectId())}${repository(data)}</div>`;
  }
  function startWizard(name = "") {
    if (wizard?.open || !repositoryData?.canManage || !repositoryData.configured) return;
    const project = getProjectId();
    const url = api("repository");
    const opener = document.activeElement;
    const isCurrent = () => active === "repository" && project === getProjectId();
    const opened = openRepositorySetup({
      project, data:repositoryData, suggested:name, request:payload=>request(url,payload), escape, announce,
      update(data) { if (isCurrent()) showRepositories(data); },
      restoreFocus() {
        if (wizard !== opened) return;
        wizard = undefined;
        if (isCurrent()) {
          const resume = [...page.querySelectorAll("[data-repo-resume]")].find(b=>b.dataset.repoResume===name);
          (opener?.isConnected && opener !== document.body ? opener : resume || page.querySelector("[data-repo-add]"))?.focus();
        }
      }
    });
    wizard = opened;
  }
  async function render(view, detail) {
    active=view;
    detailId=detail;
    const marker=++revision;
    page.setAttribute("aria-busy","true");
    page.innerHTML='<p class="empty">Загрузка…</p>';
    try {
      let html;
      if (view==="overview") {
        html=overview();
      }
      else if (view==="repository") {
        const data = await request(api("repository"));
        if (marker !== revision) return;
        showRepositories(data);
        const suggested = repositoryName(new URLSearchParams(detail).get("name") || "");
        if (suggested && data.canManage && data.configured) {
          // Consume the deep link once so refreshing the list does not reopen the wizard.
          detailId = "";
          startWizard(suggested);
        }
        return;
      }
      else {
        const [item, search] = (detail || "").split("?");
        const params = new URLSearchParams(search);
        allProjects = params.get("scope") === "all" || !getProjectId();
        issueRepository = allProjects ? "" : params.get("repository") || "";
        issueId = item && !Object.hasOwn(filters,item) ? item : "";
        const fromDetail = params.get("filter");
        filter = issueId ? (Object.hasOwn(filters,fromDetail) ? fromDetail : "open") : item || "open";
        if (issueId) html=issueCard(await request(api("issue",{id:issueId})));
        else {
          const listParams = {filter, offset};
          if (allProjects) listParams.scope = "all";
          if (issueRepository) listParams.repository = issueRepository;
          const [data, sources] = await Promise.all([request(api("issues",listParams)),
            getProjectId() ? request(api("project/sources")) : {repositories:[]}]);
          if (marker !== revision) return;
          const names = sources.repositories;
          if (issueRepository) {
            const known = names.find(name => name.toLowerCase() === issueRepository.toLowerCase());
            if (known) issueRepository = known;
            else names.push(issueRepository);
          }
          html=issueList(data,names);
        }
      }
      if (marker===revision) page.innerHTML=`<div class="portal project-screen">${view==="issues" ? projectTabs("issues",getProjectId()) : ""}${html}</div>`;
    } catch (error) {
      if (marker===revision) page.innerHTML=`<p class="empty" role="alert">${escape(error.message)}</p><button class="button" data-project-refresh>Повторить</button>`;
    } finally {if (marker===revision) page.setAttribute("aria-busy","false");}
  }
  page.addEventListener("change", e=>{
    if(e.target.matches("[data-issue-filter]")) {offset=0;location.hash=projectRoute("issues",e.target.value,issueScope());}
    if(e.target.matches("[data-issue-scope]")) {
      const value=e.target.value;
      offset=0;
      location.hash=projectRoute("issues",filter,{scope:value==="all" ? "all" : "",repository:["project","all"].includes(value) ? "" : value});
    }
  });
  page.addEventListener("click", e=>{
    const control=e.target.closest("button");
    if (!control || !active) return;
    if (control.hasAttribute("data-repo-add")) { startWizard(); return; }
    if (control.hasAttribute("data-repo-resume")) { startWizard(control.dataset.repoResume); return; }
    if(control.dataset.offset) offset=Math.max(0,offset+(control.dataset.offset==="next"?50:-50));
    if(control.dataset.offset || control.hasAttribute("data-project-refresh")) render(active,detailId);
  });
  page.addEventListener("submit",async e=>{
    const form=e.target;
    const kind=form.dataset.projectForm;
    if(!kind) return;
    e.preventDefault();
    if(form.dataset.busy) return;
    const payload=Object.fromEntries(new FormData(form));
    if(kind==="issue") {
      payload.assignee=payload.assignee || null;
      const changed = ["status","reason","expiresAt"].some(key => {
        const field = form.elements[key];
        return field instanceof HTMLSelectElement ? [...field.options].some(o=>o.selected!==o.defaultSelected) :
          field.value !== field.defaultValue;
      });
      if (!changed) {
        delete payload.status;
        delete payload.reason;
        delete payload.expiresAt;
      }
    }
    else {
      payload.action=e.submitter?.value;
      if (!payload.action) return;
      if (payload.action==="pull_requests") payload.enabled=payload.enabled==="true";
      const name=form.closest("[data-repo-card]")?.dataset.repoCard;
      if (payload.action==="disconnect" && !window.confirm(`Отключить репозиторий ${name} от проекта?`)) return;
      if (payload.action==="cancel" && !window.confirm(`Отменить запрос подключения ${name}?`)) return;
    }
    const marker=revision;
    form.dataset.busy="true";
    try {
      const data=await request(api(kind,kind==="issue"?{id:issueId}:{}),payload);
      if(marker!==revision) return;
      if(data.run) location.hash="runs/"+data.run.id;
      else {await render(active,detailId);announce("Изменения сохранены");}
    } catch(error){if(form.isConnected) form.querySelector('[role="alert"]').textContent=error.message;}
    finally{delete form.dataset.busy;}
  });
  function leave() {
    repositoryData = undefined;
    if (wizard?.open) wizard.close();
    wizard = undefined;
    active = null;
    offset = 0;
    revision++;
  }
  return {render, leave};
}
