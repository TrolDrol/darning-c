import {createCanvas, labels, localTimezone, nodeIcon} from '/studio_canvas.js';
import {bindReportActions, reportMarkup} from '/studio_report.js';
import {mountIntegrations} from '/studio_integrations.js';
import {libraryMarkup, mountLibrary} from '/studio_library.js';
import {githubFields, mountGithub, githubSelection, boundSourceOptions, repositoryName, archiveBase64, projectUpload} from '/source_picker.js';

const nodeGroups = [
  ["Запуск", [["manual", "По нажатию кнопки"], ["schedule", "По времени и часовому поясу"]]],
  ["Данные и проверки", [["source", "GitHub, папка или архив"], ["regex", "Совпадения в списке строк"], ["secrets", "Секреты в тексте"], ["sast", "Код и конфигурация"], ["sca", "Зависимости Gradle и Maven"]]],
  ["Обработка", [["condition", "Разветвление по условию"], ["explain", "Рекомендации по находкам"], ["verify", "Проверка рекомендаций"]]],
  ["Доставка", [["notify", "Telegram или почта"]]]
];

const toolbarPaths = {
  add: "M12 5v14M5 12h14", run: "m7 4 13 8-13 8z", save: "m4 12 5 5L20 6",
  history: "M3 11a9 9 0 1 1 2 7M3 5v6h6m3-5v6l4 3",
  menu: "M4 12h1m6 0h1m6 0h1", close: "m6 6 12 12m0-12L6 18",
  search: "M15 15l5 5M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0",
  back: "m10 5-7 7 7 7M4 12h17"
};
function icon(key) {
  return `<svg aria-hidden="true" focusable="false" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="${toolbarPaths[key]}"/></svg>`;
}
function editorHash(automationId, runId = "") {
  const route = "#scenarios" + (runId ? "/automation/" + encodeURIComponent(runId) : "");
  return automationId && automationId !== "default" ? route + "?" + new URLSearchParams({automationId}) : route;
}

function mountMetricsHelp(form){
  const help=form.querySelector("[data-metrics-help]"), tip=form.querySelector("#metrics-help");
  let pinned=false;
  function show(value){tip.hidden=!value;help.setAttribute("aria-expanded",String(value));}
  help.addEventListener("pointerenter",event=>{if(event.pointerType==="mouse")show(true);});
  const group=help.closest(".metrics-option");
  group.addEventListener("pointerleave",()=>{if(!pinned&&document.activeElement!==help)show(false);});
  help.addEventListener("focus",()=>show(true));
  help.addEventListener("blur",()=>{pinned=false;show(false);});
  help.addEventListener("click",()=>{pinned=!pinned;show(pinned);});
  form.addEventListener("keydown",event=>{
    if(event.key==="Escape"&&!tip.hidden){event.preventDefault();pinned=false;show(false);}
  });
  form.addEventListener("pointerdown",event=>{
    if(!group.contains(event.target)){pinned=false;show(false);}
  });
}

export function createStudio({page,request,getProjectId,hasRepositorySettings,canWrite,announce,escape:e,getSourcePolicy}){
  let generation=0,canvas,timer,session;
  const drafts=new Map();
  const dirty=()=>Boolean(session?.changed);
  function leave(){
    generation++;clearTimeout(timer);canvas?.dispose();canvas=null;
    if(session?.changed)drafts.set(session.draftKey,session.graph);
    session?.dialog?.close();session=null;
  }
  const clear=()=>{leave();drafts.clear();};
  const endpoint=(project,suffix="")=>`/api/studio${suffix}?project=${encodeURIComponent(project)}`;
  function scheduledRepository(s) {
    const ref=s.graph.nodes.find(n=>n.type==="source")?.params?.repository;
    return ref==="@bound" ? "@bound:"+(s.legacyBoundId||"") : ref;
  }
  function sourceStatus(s){
    const ref=scheduledRepository(s);
    s.section.querySelector("[data-source-warning]").hidden=s.snapshot
      ||s.repositories.some(item=>"@bound:"+item.bindingId===ref)||!s.graph.nodes.some(n=>n.type==="schedule");
  }
  function mark(){
    if(!session)return;session.changed=true;canvas?.statuses([]);
    sourceStatus(session);
    session.section.querySelector("[data-draft-label]").textContent="Есть несохранённые изменения";
    updateEditorState(session);
  }
  function updateEditorState(s) {
    const graph = s.snapshot ? s.report.graph : s.graph;
    const empty = graph.nodes.length === 0;
    s.section.querySelector("[data-empty-graph]").hidden = !empty || s.snapshot;
    const save = s.section.querySelector("[data-save-graph]");
    if (save) save.disabled = !s.changed || s.saving;
    const run = s.section.querySelector('[data-modal="run"]');
    if (run) run.disabled = empty;
    const schedule = s.section.querySelector("[data-library-schedule]");
    if (schedule) {
      schedule.hidden = s.snapshot || !s.scheduleHeld || !s.graph.nodes.some(n=>n.type==="schedule");
      schedule.querySelector("button")?.toggleAttribute("disabled", Boolean(s.saving));
    }
    s.section.querySelector("[data-draft-label]").classList.toggle("is-dirty", s.changed && !s.snapshot);
  }
  function closeDrawer(s, restoreFocus=false) {
    s.section.querySelectorAll(".automation-drawer").forEach(drawer=>drawer.hidden=true);
    s.section.querySelectorAll("[data-picker]").forEach(button=>button.setAttribute("aria-expanded","false"));
    if(restoreFocus && s.drawerOpener?.isConnected) s.drawerOpener.focus({preventScroll:true});
    s.drawerOpener=null;s.addOrigin=null;
  }
  function filterNodes(s) {
    const drawer=s.section.querySelector("[data-node-catalog]");
    const search=drawer.querySelector("[data-node-search]").value.toLocaleLowerCase("ru").trim();
    const types=canvas.allowedTypes(s.addOrigin);
    const matches=type=>types.includes(type) && (s.graph.nodes.length || ["manual","schedule"].includes(type));
    let count=0;
    drawer.querySelectorAll("[data-picker-type]").forEach(button=>{
      button.hidden=!(matches(button.dataset.pickerType) && (button.textContent+" "+button.dataset.pickerType).toLocaleLowerCase("ru").includes(search));
      if(!button.hidden) count++;
    });
    drawer.querySelectorAll("[data-node-group]").forEach(group=>group.hidden=!group.querySelector("[data-picker-type]:not([hidden])"));
    drawer.querySelector("[data-no-matches]").hidden=Boolean(count);
  }
  function openCatalog(s,origin=null) {
    if(!canWrite()||s.snapshot)return;
    const opener=document.activeElement;
    closeDrawer(s);s.drawerOpener=opener;s.addOrigin=origin;
    const el=s.section.querySelector("[data-node-catalog]");
    el.querySelector("h2").textContent=!s.graph.nodes.length?"Первый шаг":origin?"Следующий шаг":"Добавить шаг";
    const search=el.querySelector("[data-node-search]");
    search.value="";filterNodes(s);el.hidden=false;search.focus({preventScroll:true});
    s.section.querySelectorAll("[data-picker]").forEach(button=>button.setAttribute("aria-expanded","true"));
  }
  function openInspector(s) {
    const opener=document.activeElement;
    closeDrawer(s);s.drawerOpener=opener;
    s.section.querySelector("[data-node-inspector]").hidden=false;
  }
  function openHistory(s,scroll=true) {
    const history=s.section.querySelector("[data-run-log]");
    history.open=true;
    if(scroll)history.scrollIntoView({block:"start"});
    if(!s.report&&s.runs.length && !s.read) selectRun(s.runs[0].id,false,false);
  }
  function showRunOrder(){
    const hist=session.section.querySelector("[data-history]"),id=session.report?.id||"";
    hist.innerHTML=`<option value="">Выберите запуск</option>`+session.runs.map(r=>`<option value="${e(r.id)}">${e(String(r.id).slice(0,8))} · ${e(({queued:"В очереди",running:"Выполняется",done:"Готово",completed:"Завершён",passed:"Пройден",review:"Есть замечания",failed:"Ошибка",partial:"Частичный результат"})[r.status]||r.status)}</option>`).join("");
    hist.value=id;
  }
  function mode(snapshot, redraw=true){
    const s=session, previous=s.snapshot;s.snapshot=Boolean(snapshot&&s.report?.graph);
    sourceStatus(s);
    const label=s.section.querySelector("[data-draft-label]"), toggle=s.section.querySelector("[data-trace-mode]");
    label.textContent=s.snapshot?"Снимок графа · "+s.report.id.slice(0,8):s.changed?"Есть несохранённые изменения":canWrite()?"Сохранённый сценарий":"Режим просмотра";
    toggle.hidden=!s.report?.graph;toggle.textContent=s.snapshot?"Вернуться к сценарию":"Путь запуска";
    s.section.querySelectorAll("[data-edit-only]").forEach(el=>el.hidden=s.snapshot);
    if (previous !== s.snapshot) closeDrawer(s);
    updateEditorState(s);
    if(redraw)canvas.draw();
    if(s.snapshot)canvas.statuses(s.report.stages);
  }
  async function selectRun(id,scroll=false,snapshot=true){
    clearTimeout(timer);const s=session, version=++s.read;
    const target=s.section.querySelector("[data-report]");
    if(!id){s.report=null;mode(false);target.innerHTML="<p>Выберите проверку из истории.</p>";return;}
    try{
      const run=await request(endpoint(s.project,"/run")+"&id="+encodeURIComponent(id));if(s!==session||version!==s.read)return;
      if(run.automationId && run.automationId!==s.automationId){
        location.replace(editorHash(run.automationId,id));return;
      }
      const showSnapshot=snapshot===null?s.snapshot:snapshot;
      const redraw=s.report?.id!==id||s.snapshot!==showSnapshot;s.report=run;
      const row=s.runs.find(r=>r.id===id);if(row)row.status=run.status;else s.runs.unshift({id,status:run.status});
      const opened=new Set([...target.querySelectorAll("details[open][data-packet]")].map(el=>el.dataset.packet));
      showRunOrder();target.innerHTML=reportMarkup(run,e,labels);
      target.querySelectorAll("[data-packet]").forEach(el=>el.open=opened.has(el.dataset.packet));
      mode(showSnapshot,redraw);
      if(scroll)openHistory(s);
      if(["queued","running","pending"].includes(run.status))timer=window.setTimeout(()=>selectRun(id,false,null),1400);
    }catch(error){
      if(s===session&&version===s.read)target.innerHTML=`<p role="alert">${e(error.message)}</p><button type="button" class="button" data-read-run="${e(id)}">Повторить загрузку</button>`;
    }
  }
  function modal(kind,sourceParams=new URLSearchParams()){
    const s=session,d=s.dialog;
    const repository=repositoryName(sourceParams.get("repository")||"");
    const revision=sourceParams.get("revision");
    const boundRepository=repository&&s.repositories.find(item=>item.repository.toLowerCase()===repository.toLowerCase());
    const preferred=repository ? sourceParams.get("binding") || (boundRepository&&"@bound:"+boundRepository.bindingId) : scheduledRepository(s);
    const missingBound=preferred&&!s.repositories.some(item=>"@bound:"+item.bindingId===preferred);
    const content={
      run:`<h2>Источник проверки</h2><label class="field">Проверить<select name="source" required>${missingBound?'<option value="" disabled selected>Выберите источник для этого запуска</option>':""}${boundSourceOptions(s.repositories,e)}<option value="github">Указать ссылку на GitHub</option><option value="local">Выбрать папку на компьютере</option><option value="files">Выбрать отдельные файлы</option><option value="zip">Загрузить ZIP</option></select></label>
        <div data-source-github hidden>${githubFields()}<small data-bound-tip hidden>По умолчанию проверим последнюю версию основной ветки. Можно выбрать более ранний коммит.</small></div>
        <div data-directory hidden><label class="field">Каталог проекта<input type="file" name="directory" webkitdirectory multiple></label></div>
        <div data-files hidden><label class="field">Файлы проекта<input type="file" name="files" multiple></label></div>
        <div data-archive hidden><label class="field">ZIP-архив проекта · до 8 МБ<input type="file" name="archive" accept=".zip,application/zip"></label></div>
        <details data-advisories hidden><summary>Справочник уязвимостей (SCA)</summary><p id="sca-help">Встроенный справочник используется автоматически. Чтобы сверить зависимости со своим набором, выберите JSON со списком vulnerabilities.</p><label class="field">Свой справочник, необязательно<input name="database" type="file" accept=".json" aria-describedby="sca-help"></label></details>
        <div class="metrics-option"><label><input type="checkbox" name="dependencyMetrics" aria-describedby="metrics-help"> Запросить публичные метрики зависимостей</label>
        <button type="button" data-metrics-help aria-label="Какие данные используются для метрик" aria-expanded="false" aria-controls="metrics-help" aria-describedby="metrics-help">?</button>
        <p id="metrics-help" role="tooltip" hidden>Сервис передаст названия и версии зависимостей в deps.dev и запросит данные репозиториев на GitHub. В отчёте появятся дата создания репозитория и число скачиваний файлов последних десяти релизов. Просмотры за 14 дней доступны с разрешения владельца.</p></div>`,
      create:`<h2>Новая автоматизация</h2><label class="field">Название<input name="name" maxlength="80" required placeholder="Например, проверка перед релизом"></label>
        <button type="button" class="link-button" data-modal="library">Выбрать сценарий из библиотеки</button>`,
      generate:`<h2>Сценарий по описанию</h2><label class="field">Что проверять и когда<textarea required name="prompt" maxlength="2000" rows="4" placeholder="Проверяй код каждый день в 14:00 UTC и пиши мне в Телеграм"></textarea></label><small>Enter собирает сценарий. Shift+Enter добавляет строку.</small>`,
      template:`<h2>Публикация в библиотеку</h2>
        <label class="field">Кто увидит сценарий<select name="scope"><option value="organization">Только сотрудники предприятия</option>
        <option value="community">Все пользователи «Штопки»</option></select></label>
        <label class="field">Название<input name="name" maxlength="100" required></label>
        <label class="field">Для чего подходит сценарий<textarea name="description" required maxlength="500" rows="2"></textarea></label>
        <small>Публикуется копия графа. Название и описание увидит выбранная аудитория. Репозиторий, модель, папки и внутренние пути в условиях получатель настроит в своём проекте.</small>
        ${s.graph.nodes.some(node => node.type === "regex") ? "<small>Регулярные выражения входят в шаблон и будут видны получателям. Список строк, введённый вручную, каждый заполняет у себя.</small>" : ""}`,
      library:libraryMarkup(canWrite(), canWrite()&&!s.snapshot&&s.graph.nodes.length>0)
    };
    const actions={run:"Запустить проверку",create:"Создать",generate:"Собрать сценарий",template:"Опубликовать"};
    d.innerHTML=`<form class="studio-dialog-form" data-operation="${kind}"><button type="button" class="studio-close" aria-label="Закрыть" data-close>×</button>
      ${content[kind]}<p role="alert" class="run-error"></p>${actions[kind]?`<div class="portal-actions"><button type="submit" class="button primary">${actions[kind]}</button><button type="button" class="button" data-close>Отмена</button></div>`:""}</form>`;
    if(kind==="run"){
      const form=d.querySelector("form");
      const github=mountGithub(form,{request,project:s.project,bindingAvailable:hasRepositorySettings(),allowEmpty:true,
        initialRepository:repository,initialRevision:/^[a-f0-9]{40}$/.test(revision)?revision:""});
      if(repository&&revision&&preferred)form.dataset.reportBinding=preferred;
      if(preferred&&!missingBound)form.elements.source.value=preferred;
      else if(repository&&!missingBound)form.elements.source.value="github";
      mountMetricsHelp(form);
      function sourceChanged(){
        const source=form.elements.source.value,local=source==="local",zip=source==="zip",files=source==="files";
        const bound=s.repositories.find(item=>"@bound:"+item.bindingId===source);
        form.querySelector("[data-source-github]").hidden=!(bound||source==="github");
        form.querySelector("[data-bound-tip]").hidden=!bound||source===form.dataset.reportBinding;
        github.setSource(Boolean(bound)||source==="github",bound?.repository,bound ? source : "");
        form.querySelector("[data-directory]").hidden=!local;form.elements.directory.required=local;
        form.querySelector("[data-files]").hidden=!files;form.elements.files.required=files;
        form.querySelector("[data-archive]").hidden=!zip;form.elements.archive.required=zip;
        form.querySelector("[data-advisories]").hidden=!(local||zip||files);
      }
      form.elements.source.addEventListener("change",sourceChanged);sourceChanged();
    }
    if(kind==="generate"&&s.pendingPrompt){d.querySelector("[name=prompt]").value=s.pendingPrompt;s.pendingPrompt="";}
    d.querySelector("h2").id="studio-dialog-title";if(!d.open)d.showModal();
    if(kind==="library") mountLibrary(d.querySelector("form"), {
      url:endpoint(s.project,"/library"), projectUrl:endpoint(s.project), request, escape:e, writable:canWrite(),
      scope:sourceParams.get("scope"), openCopy:copy=>{
        d.close();location.hash=editorHash(copy.automationId);announce("Копия создана в вашем проекте.");
      }
    });
    d.querySelector("input:not([type=file]), textarea, select")?.focus();
  }
  async function upload(form){
    const all=Array.from(form.elements.directory.files);
    if (!all.length) throw Error("Выберите папку проекта.");
    return projectUpload(all,getSourcePolicy(),true);
  }
  async function action(kind,form,enableSchedule=false){
    const s=session;if(!s||s.busy||!canWrite())return;
    const button=form?.querySelector("[type=submit]");
    const buttonLabel=button?.textContent;
    const errorPlace=form?.querySelector("[role=alert]");
    if(errorPlace)errorPlace.textContent="";
    s.busy=true;if(button)button.disabled=true;
    if(kind==="save"){s.saving=true;updateEditorState(s);}
    if(kind==="generate"){form.setAttribute("aria-busy","true");button.textContent="Собираем сценарий…";}
    const editBefore=JSON.stringify(s.graph);
    try{
      const params={action:kind,automationId:s.automationId};
      if(["save","template","run"].includes(kind))params.graph=structuredClone(s.graph);
      if(kind==="run"){
        const source=form.elements.source.value;
        if(source==="local")Object.assign(params,await upload(form));
        else if(source==="files")Object.assign(params,await projectUpload([...form.elements.files.files],getSourcePolicy(),false));
        else if(source==="zip")params.archive=await archiveBase64(form.elements.archive.files[0]);
        else if(source==="github"||source===form.dataset.reportBinding)Object.assign(params,githubSelection(form));
        else if(s.repositories.some(item=>"@bound:"+item.bindingId===source)){
          params.repository=source;
          if(form.elements.githubRevision.value)params.revision=form.elements.githubRevision.value;
          else if(form.querySelector("[data-github-picker]").dataset.emptyRepository==="true")params.emptyRepository=true;
        }else throw Error("Выберите источник для проверки.");
        const database=form.elements.database.files[0];
        if(["local","zip","files"].includes(source)&&database){
          if(database.size>500000)throw Error("Справочник SCA превышает 500 КБ.");
          try{params.advisories=JSON.parse(await database.text());}catch{throw Error("Справочник SCA должен быть корректным JSON. Исправьте файл или уберите его, чтобы использовать встроенный справочник.");}
        }
        params.dependencyMetrics=form.elements.dependencyMetrics.checked;
      }
      if(kind==="template"){params.name=form.elements.name.value;params.description=form.elements.description.value;params.scope=form.elements.scope.value;}
      if(kind==="save"&&enableSchedule)params.enableSchedule=true;
      if(kind==="create")params.name=form.elements.name.value.trim();
      if(kind==="generate"){params.prompt=form.elements.prompt.value;params.timezone=localTimezone();}
      if(s!==session)return;
      const answer=await request(endpoint(s.project),params);
      if(s!==session)return;
      if(kind==="generate"&&(!s.dialog.open||!s.dialog.contains(form)))return;
      if(kind==="create"){
        s.dialog.close();location.hash=editorHash(answer.automationId);
        announce("Автоматизация создана. Выберите первый шаг.");
      }else if(kind==="save"){
        s.scheduleHeld=Boolean(answer.scheduleHeld);
        if(editBefore===JSON.stringify(s.graph)){
          drafts.delete(s.draftKey);s.changed=false;s.section.querySelector("[data-draft-label]").textContent=answer.draft?"Черновик сохранён":"Сценарий сохранён";
          updateEditorState(s);
        }
        announce(answer.draft ? "Черновик сохранён." + (answer.scheduleTime?" Расписание продолжит выполнять последнюю готовую версию.":"") : "Сценарий сохранён.");
      }else if(kind==="run"){
        s.dialog.close();await selectRun(answer.id);
        if(s===session)s.section.querySelector(".studio-editor").scrollIntoView({block:"start"});
      }else if(kind==="template"){
        modal("library",new URLSearchParams({scope:params.scope}));announce("Сценарий опубликован.");
      }else{
        mode(false,false);s.graph=structuredClone(answer.graph);mark();canvas.draw(kind==="generate");canvas.fit(false);
        s.dialog.close();announce("Сценарий добавлен в редактор.");
      }
    }catch(error){
      if(s===session){
        if(errorPlace)errorPlace.textContent=error.message;else announce(error.message,true);
        if(kind==="generate"&&errorPlace&&s.dialog.open&&s.dialog.contains(form)){
          const settings=s.section.querySelector("[data-studio-integrations] details");
          if(settings?.querySelector("[data-profile-form]")){
            const link=document.createElement("button");
            link.type="button";link.className="button";link.textContent="Настроить подключение модели";
            link.addEventListener("click",()=>{
              s.pendingPrompt=form.elements.prompt.value;s.dialog.close();
              settings.closest("[data-studio-integrations]").hidden=false;settings.open=true;
              settings.scrollIntoView({block:"center"});settings.querySelector("[name=mode]").focus();
            });
            errorPlace.append(" ",link);
          }else errorPlace.append(" Настройки подключения доступны руководителю проекта.");
        }
      }
    }
    finally{
      s.busy=false;
      if(kind==="save"&&session===s){s.saving=false;updateEditorState(s);}
      if(button){button.disabled=false;button.textContent=buttonLabel;}
      if(kind==="generate")form.removeAttribute("aria-busy");
    }
  }

  async function openReport(id){
    leave();const version=generation, project=getProjectId();
    id=(id||"").split("?")[0];
    page.innerHTML=`<section class="studio"><header class="portal-heading studio-heading"><h1>Отчёт проверки</h1></header>
      <section class="studio-reports" data-shared-report><p>Загружаем отчёт…</p></section></section>`;
    const host=page.querySelector("[data-shared-report]");
    let run;
    bindReportActions(host,project,()=>run,announce);
    async function read(){
      try{
        if(!/^[a-f0-9]{32}$/.test(id||""))throw Error("Проверьте ссылку на отчёт.");
        const data=await request(endpoint(project,"/run")+"&id="+encodeURIComponent(id));
        if(version!==generation)return;
        run=data;
        host.innerHTML=reportMarkup(run,e,labels)+`<p><a href="${e(editorHash(run.automationId,run.id))}">Посмотреть схему этого запуска</a></p>`;
        if(["running","pending","queued"].includes(run.status))timer=window.setTimeout(read,1400);
      }catch(error){
        if(version===generation){
          host.innerHTML=`<p role="alert">${e(error.message)}</p><button type="button" class="button">Повторить загрузку отчёта</button>`;
          host.querySelector("button").onclick=read;
        }
      }finally{if(version===generation)page.setAttribute("aria-busy","false");}
    }
    page.setAttribute("aria-busy","true");await read();
  }

  async function open(detail){
    leave();const version=generation, project=getProjectId();
    const [actionName,query=""]=(detail||"").split("?");
    const sourceParams=new URLSearchParams(query);
    const automationId=sourceParams.get("automationId")||"default";
    page.setAttribute("aria-busy","true");page.innerHTML='<p class="empty">Открываем сценарий…</p>';
    try{
      const state=await request(endpoint(project)+"&templates=0&automationId="+encodeURIComponent(automationId));if(version!==generation)return;
      const draftKey=JSON.stringify([project,automationId]);
      const s={project,repositories:state.boundRepositories||[],legacyBoundId:state.legacyBoundId,
        automationId,draftKey,graph:structuredClone(drafts.get(draftKey)||state.graph),
        scheduleHeld:Boolean(state.scheduleHeld),runs:state.runs||[],read:0,changed:drafts.has(draftKey)};
      const writable=canWrite();
      const choices=state.automations||[{id:"default",name:"Сценарий проекта"}];
      page.innerHTML=`<section class="studio automation-screen" aria-labelledby="studio-title">
        <header class="automation-header">
          <div class="automation-heading"><h1 id="studio-title">Автоматизация</h1>
            <label class="automation-chooser"><span class="visually-hidden">Сценарий проекта</span><select data-automation-select>
              ${choices.map(a=>`<option value="${e(a.id)}" ${a.id===automationId?"selected":""}>${e(a.name)}</option>`).join("")}
            </select></label>${writable?`<button type="button" class="button automation-create" data-modal="create" aria-label="Новая автоматизация" title="Новая автоматизация">${icon("add")}<span>Новая</span></button>`:""}</div>
          <div class="automation-header-actions"><small data-draft-label aria-live="polite"></small>
            ${writable?`<button type="button" class="button automation-save" data-edit-only data-save-graph aria-label="Сохранить сценарий" title="Сохранить сценарий">${icon("save")}<span>Сохранить</span></button>`:""}
            <details class="automation-menu" data-actions><summary aria-label="Действия со сценарием" title="Действия со сценарием">${icon("menu")}</summary>
              <div class="automation-menu-items">${writable?'<button type="button" data-edit-only data-modal="generate">Собрать по описанию</button>':""}
                <button type="button" data-modal="library">Библиотека сценариев</button>
                <button type="button" data-integrations>Модель и интеграции</button>
              </div></details></div>
        </header>
        <p data-source-warning class="automation-warning" hidden>Для расписания выберите подключённый репозиторий в настройках шага «Репозиторий».</p>
        <div class="automation-warning" data-library-schedule hidden>Расписание копии приостановлено. Проверьте время и репозиторий.
          ${writable?'<button type="button" class="button" data-enable-schedule>Сохранить и включить расписание</button>':""}</div>
        <section class="studio-editor automation-stage" aria-label="Редактор сценария">
          <div class="studio-scroller" tabindex="0" aria-label="Холст сценария"><div class="studio-sheet"><div class="studio-plane"></div></div></div>
          <div class="automation-top-tools">${writable?`<button class="automation-add" type="button" data-edit-only data-picker aria-controls="automation-catalog" aria-expanded="false" title="Добавить шаг">${icon("add")}<span>Добавить шаг</span></button>`:""}
            <button type="button" data-trace-mode hidden>Путь запуска</button></div>
          <div class="automation-empty" data-empty-graph hidden>
            ${writable?`<button type="button" data-picker aria-controls="automation-catalog" aria-expanded="false"><span>${icon("add")}</span>Добавить первый шаг</button>`:"<p>В сценарии пока нет шагов.</p>"}
          </div>
          <div class="automation-bottom-tools">
            <div class="automation-zoom" role="group" aria-label="Масштаб холста">
              <button type="button" aria-label="Уменьшить" data-zoom="-0.1">−</button>
              <button type="button" data-studio-fit aria-label="Вписать граф в экран" title="Вписать граф в экран">100 %</button>
              <button type="button" aria-label="Увеличить" data-zoom="0.1">+</button>
            </div>
            ${writable?`<button class="automation-run" type="button" data-edit-only data-modal="run">${icon("run")} Запустить проверку</button>`:""}
            <button type="button" class="automation-history" data-show-history aria-label="История запусков" aria-controls="automation-log" aria-expanded="false">${icon("history")}<span>История</span></button>
          </div>
          ${writable?`<aside id="automation-catalog" class="automation-drawer" data-node-catalog aria-labelledby="catalog-title" hidden>
            <header><h2 id="catalog-title">Добавить шаг</h2><button type="button" data-close-drawer aria-label="Закрыть каталог">${icon("close")}</button></header>
            <label class="automation-search">${icon("search")}<span class="visually-hidden">Поиск шагов</span><input type="search" data-node-search placeholder="Поиск шагов" autocomplete="off"></label>
            <div class="automation-node-list">${nodeGroups.map(([name,items])=>`<section data-node-group><h3>${e(name)}</h3>
              ${items.map(([type,hint])=>`<button type="button" draggable="true" data-picker-type="${type}"><span class="catalog-icon" data-type="${type}">${nodeIcon(type)}</span><span><strong>${e(labels[type])}</strong><small>${e(hint)}</small></span></button>`).join("")}</section>`).join("")}
              <p data-no-matches hidden>Подходящих шагов нет.</p></div></aside>`:""}
          <aside class="automation-drawer automation-property-drawer" data-node-inspector aria-label="Параметры шага или связи" hidden>
            <button type="button" class="automation-inspector-close" data-close-drawer aria-label="Закрыть параметры">${icon("close")}</button>
            <div class="studio-inspector"></div></aside>
        </section>
        <div data-studio-integrations hidden></div>
        <details id="automation-log" class="studio-reports automation-log" data-run-log><summary>${icon("history")} История и результаты запусков</summary>
          <label class="field">Запуск<select data-history></select></label>
          <div data-report>${s.runs.length?"Выберите проверку из истории.":"Здесь появится отчёт первого запуска."}</div></details>
        <dialog class="studio-dialog" aria-labelledby="studio-dialog-title"></dialog></section>`;
      s.section=page.firstElementChild;s.dialog=s.section.querySelector("dialog");session=s;
      bindReportActions(s.section.querySelector("[data-report]"),project,()=>s.report,announce);
      mountIntegrations(s.section.querySelector("[data-studio-integrations]"),{request,project:s.project,overview:state,canWrite:canWrite()});
      canvas=createCanvas({section:s.section,getGraph:()=>s.snapshot?s.report.graph:s.graph,getReport:()=>s.snapshot?s.report:null,repositories:s.repositories,legacyBoundId:s.legacyBoundId,
        canWrite:()=>!s.snapshot&&canWrite(),escape:e,onChange:mark,announce,getAddOrigin:()=>s.addOrigin,
        onAddRequest:origin=>openCatalog(s,origin),onInspect:()=>openInspector(s)});
      canvas.draw();mode(false,false);showRunOrder();
      s.section.addEventListener("click",event=>{
        const menu=s.section.querySelector("[data-actions]");
        if(!menu.contains(event.target)||event.target.closest("button"))menu.open=false;
        const b=event.target.closest("button");if(!b)return;
        if(b.hasAttribute("data-trace-mode")){mode(!s.snapshot);return;}
        if(b.hasAttribute("data-picker")){openCatalog(s);return;}
        if(b.hasAttribute("data-close-drawer")){closeDrawer(s,true);return;}
        if(b.hasAttribute("data-picker-type")){
          const origin=s.addOrigin;closeDrawer(s);
          canvas.addNode(b.dataset.pickerType,origin);return;
        }
        if(b.hasAttribute("data-show-history")){openHistory(s);s.section.querySelector("[data-history]").focus({preventScroll:true});return;}
        if(b.hasAttribute("data-integrations")){
          const host=s.section.querySelector("[data-studio-integrations]");
          host.hidden=false;host.querySelector("details").open=true;host.scrollIntoView({block:"start"});host.querySelector("summary").focus({preventScroll:true});return;
        }
        if(b.hasAttribute("data-modal")&&(canWrite()||b.dataset.modal==="library"))modal(b.dataset.modal);
        if(b.hasAttribute("data-save-graph"))action("save");
        if(b.hasAttribute("data-enable-schedule"))action("save",null,true);
        if(b.hasAttribute("data-close"))s.dialog.close();
        if(b.hasAttribute("data-read-run"))selectRun(b.dataset.readRun);
      });
      s.section.addEventListener("change",event=>{
        if(event.target.matches("[data-history]"))selectRun(event.target.value);
        if(event.target.matches("[data-automation-select]"))location.hash=editorHash(event.target.value);
      });
      s.section.querySelector("[data-node-search]")?.addEventListener("input",()=>filterNodes(s));
      s.section.addEventListener("keydown",event=>{
        if(event.key==="Escape"&&!s.dialog.open&&s.section.querySelector(".automation-drawer:not([hidden])")){
          event.preventDefault();closeDrawer(s,true);
        }else if(event.key==="Escape"&&s.section.querySelector("[data-actions]").open){
          s.section.querySelector("[data-actions]").open=false;s.section.querySelector("[data-actions] summary").focus();
        }else if(event.key==="Enter"&&event.target.matches("[data-node-search]")){
          event.preventDefault();s.section.querySelector("[data-picker-type]:not([hidden])")?.click();
        }
      });
      s.section.querySelector("[data-run-log]").addEventListener("toggle",event=>{
        s.section.querySelector("[data-show-history]").setAttribute("aria-expanded",String(event.target.open));
        if(event.target.open)openHistory(s,false);
        else s.section.querySelector("[data-show-history]").focus({preventScroll:true});
      });
      s.dialog.addEventListener("keydown",ev=>{
        if(ev.target.name==="prompt"&&ev.key==="Enter"&&!ev.shiftKey&&!ev.isComposing){
          ev.preventDefault();if(!s.busy)ev.target.form.requestSubmit();
        }
      });
      s.dialog.addEventListener("submit",ev=>{ev.preventDefault();if(ev.target.dataset.operation!=="library")action(ev.target.dataset.operation,ev.target);});
      if(["start","run"].includes(actionName)){if(writable)modal("run",sourceParams);}
      else if(actionName==="library")modal("library",sourceParams);
      else if(actionName)await selectRun(actionName);
    }catch(error){
      if(version===generation)page.innerHTML=`<section class="panel"><h1>Сценарии</h1><p role="alert">${e(error.message)}</p><button class="button" id="studio-retry">Повторить загрузку</button></section>`;
      page.querySelector("#studio-retry")?.addEventListener("click",()=>open(detail));
    }finally{if(version===generation)page.setAttribute("aria-busy","false");}
  }
  window.addEventListener("beforeunload",event=>{if(dirty()||drafts.size){event.preventDefault();event.returnValue="";}});
  return {open,openReport,leave,dirty,clear};
}
