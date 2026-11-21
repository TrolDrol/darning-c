// Source selection shared by manual and automated checks.
let nextPickerId=0;
const repositoryHint="Введите адрес https://github.com/владелец/репозиторий или имя в формате владелец/репозиторий.";

export function repositoryName(value){
  const name=value.trim().replace(/^https:\/\/github\.com\//i,"").replace(/\/+$/,"").replace(/\.git$/,"");
  return /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/.test(name)&&![".",".."].includes(name.split("/")[1])?name:"";
}

export function boundSourceOptions(repositories, escape) {
  if (!repositories.length) return "";
  const options = repositories.map(item =>
    `<option value="@bound:${escape(item.bindingId)}">${escape(item.repository)}</option>`);
  return `<optgroup label="Подключённые репозитории">${options.join("")}</optgroup>`;
}

export function githubFields(){
  const id="github-source-"+(++nextPickerId);
  return `<div data-github-picker>
    <label class="field">Репозиторий GitHub<input name="githubRepository" placeholder="https://github.com/владелец/репозиторий" aria-describedby="${id}-status" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
    <label class="field" data-commit-field hidden>Версия для проверки<select name="githubRevision"></select></label>
    <button type="button" class="button" data-more-versions hidden>Предыдущие коммиты</button>
    <small data-github-status id="${id}-status" role="status"></small>
    <button type="button" class="button" data-retry-inline hidden>Повторить загрузку коммитов</button>
    <dialog class="github-error-dialog" role="alertdialog" aria-labelledby="${id}-title" aria-describedby="${id}-reason">
      <h3 id="${id}-title">Не удалось загрузить коммиты</h3>
      <p id="${id}-reason" data-reason></p>
      <a data-bind-repository hidden target="_blank" rel="noopener">Настроить GitHub App для этого проекта ↗</a>
      <div class="portal-actions"><button type="button" class="button primary" data-retry>Повторить</button>
      <button type="button" class="button" data-dismiss>Закрыть</button></div>
    </dialog>
  </div>`;
}

export function mountGithub(form,{request,project,bindingAvailable=false,initialRepository="",allowEmpty=false,initialRevision=""}){
  const box=form.querySelector("[data-github-picker]");
  const input=box.querySelector("[name=githubRepository]"), revisions=box.querySelector("[name=githubRevision]");
  const more=box.querySelector("[data-more-versions]"), popup=box.querySelector(".github-error-dialog");
  const field=box.querySelector("[data-commit-field]"), status=box.querySelector("[data-github-status]");
  const parentDialog=form.closest("dialog"), binding=popup.querySelector("[data-bind-repository]");
  const retryInline=box.querySelector("[data-retry-inline]");
  let page=0, timer, pending, active=false, manual=initialRepository, retryPage=1, boundRef="";
  function visible(){return active&&box.isConnected&&parentDialog.open;}
  function reset(){
    clearTimeout(timer);pending?.abort();pending=null;
    if(popup.open)popup.close();
    page=0;revisions.replaceChildren();field.hidden=more.hidden=retryInline.hidden=true;more.disabled=false;
    delete box.dataset.repository;delete box.dataset.emptyRepository;input.removeAttribute("aria-invalid");status.textContent="";
  }
  function showError(message,requestedPage,access=false){
    retryPage=requestedPage;status.textContent=message;retryInline.hidden=false;
    popup.querySelector("[data-reason]").textContent=message;
    binding.hidden=!(access&&bindingAvailable);
    if(!binding.hidden){
      const url=new URL(location.pathname,location.origin);
      url.searchParams.set("project",project);
      url.hash="projects/repositories?"+new URLSearchParams({name:repositoryName(input.value)});
      binding.href=url.href;
    }
    if(!popup.open)popup.showModal();
    popup.querySelector("[data-retry]").focus();
  }
  async function read(requestedPage){
    clearTimeout(timer);
    if(!visible())return;
    const name=repositoryName(input.value);
    if(!name){
      input.setAttribute("aria-invalid","true");showError(repositoryHint,1);return;
    }
    pending?.abort();
    const controller=new AbortController();pending=controller;
    more.disabled=true;retryInline.hidden=true;status.textContent="Загружаем историю основной ветки…";
    try{
      const result=await request("/api/source?"+new URLSearchParams({project}),{action:"commits",repository:boundRef||name,page:requestedPage},{signal:controller.signal});
      if(controller.signal.aborted||!visible())return;
      box.dataset.repository=boundRef||result.repository;page=result.page||requestedPage;
      const empty=requestedPage===1&&result.emptyRepository===true&&result.commits.length===0;
      if (allowEmpty&&empty) box.dataset.emptyRepository="true";
      const reportVersion=requestedPage===1&&result.commits.length&&initialRevision&&name.toLowerCase()===initialRepository.toLowerCase();
      if(reportVersion&&!result.commits.some(commit=>commit.sha===initialRevision)){
        revisions.add(new Option("Версия из отчёта · "+initialRevision.slice(0,8),initialRevision));
      }
      const seen=new Set(Array.from(revisions.options,o=>o.value));
      for(const commit of result.commits){
        if(seen.has(commit.sha))continue;
        const date=commit.date?new Date(commit.date).toLocaleDateString("ru-RU"):"";
        revisions.add(new Option([date,commit.message,commit.sha.slice(0,8)].filter(Boolean).join(" · "),commit.sha));
      }
      more.hidden=!result.more;field.hidden=!revisions.options.length;
      if(reportVersion)revisions.value=initialRevision;
      if(empty)status.textContent=allowEmpty?"В репозитории пока нет коммитов. Можно запустить проверку и сохранить отчёт с нулевым охватом.":"В репозитории пока нет коммитов.";
      else status.textContent=revisions.options.length?"В отчёте сохранится выбранная версия.":"В списке нет доступной версии для проверки.";
    }catch(err){
      if(controller.signal.aborted||!visible())return;
      const access=err.code==="github_repository_unavailable";
      const message=access
        ? `GitHub не открыл ${name}. Проверьте владельца и название. Репозиторий может быть частным, перемещённым или удалённым. ${bindingAvailable?"Для частного репозитория руководитель проекта может настроить доступ через GitHub App. ":""}Для разовой проверки выберите папку или ZIP.`
        : err instanceof TypeError?"Не удалось связаться с сервисом. Проверьте соединение и повторите запрос.":err.message;
      showError(message,requestedPage,access);
    }finally{if(pending===controller){pending=null;more.disabled=false;}}
  }
  function schedule(paste=false){
    reset();
    if(!active)return;
    if(repositoryName(input.value)||paste)timer=setTimeout(()=>read(1),paste?0:450);
    else status.textContent=input.value.trim()?repositoryHint:"Вставьте ссылку, и список коммитов появится автоматически.";
  }
  input.addEventListener("input",ev=>{manual=input.value;schedule(ev.inputType==="insertFromPaste");});
  more.addEventListener("click",()=>read(page+1));
  input.addEventListener("keydown",ev=>{if(ev.key==="Enter"&&!ev.isComposing){ev.preventDefault();if(!pending&&!page)read(1);else if(page)revisions.focus();}});
  popup.querySelector("[data-dismiss]").addEventListener("click",()=>{popup.close();input.focus();});
  function retry(){
    if(popup.open)popup.close();
    input.focus();if(repositoryName(input.value))read(retryPage);
  }
  popup.querySelector("[data-retry]").addEventListener("click",retry);
  retryInline.addEventListener("click",retry);
  parentDialog.addEventListener("close",()=>{active=false;reset();},{once:true});
  return {setSource(enabled,boundName="",reference=""){
    active=enabled;boundRef=reference;input.readOnly=Boolean(boundName);input.value=boundName||manual;schedule();
  }};
}

export function githubSelection(form){
  const box=form.querySelector("[data-github-picker]");
  const repository=box.dataset.repository,revision=box.querySelector("[name=githubRevision]").value;
  if(repository&&box.dataset.emptyRepository==="true"&&!revision)return {repository,emptyRepository:true};
  if(!repository||!revision)throw Error("Укажите репозиторий и дождитесь списка коммитов, чтобы выбрать версию для проверки.");
  return {repository,revision};
}

export async function projectUpload(inputFiles, policy, folder) {
  if (!policy?.ignoredDirectories || !policy.metadataOnlyNames || !policy.binaryExtensions) {
    throw Error("Не удалось получить правила чтения файлов. Обновите страницу и повторите проверку.");
  }
  const ignore = new Set(policy.ignoredDirectories);
  const names = new Set(policy.metadataOnlyNames);
  const excluded = [...policy.binaryExtensions, ...policy.metadataOnlySuffixes];
  const files = Object.create(null), paths = new Set(), unreadablePaths = [];
  const decoder = new TextDecoder("utf-8", {fatal:true});
  let bytesRead = 0, contentCount = 0;
  for (const file of inputFiles) {
    const path = folder ? file.webkitRelativePath.split("/").slice(1).join("/") : file.name;
    const parts = path.toLowerCase().split("/");
    const name = parts.pop();
    if (parts.some(part => ignore.has(part))) continue;
    if (paths.has(path)) throw Error("Совпадают имена файлов. Выберите папку, чтобы сохранить пути.");
    paths.add(path);
    if (paths.size > 12000) throw Error("В снимке больше 12 000 файлов. Выберите один модуль.");
    if (names.has(name) || excluded.some(suffix => name.endsWith(suffix)) ||
        policy.metadataOnlyPrefixes.some(prefix => name.startsWith(prefix))) continue;
    if (file.size > 300000) throw Error(`Файл «${path}» превышает 300 КБ. Выберите один модуль проекта.`);
    let bytes;
    try { bytes = new Uint8Array(await file.arrayBuffer()); }
    catch { throw Error(`Браузер не смог прочитать файл «${path}». Выберите папку заново или загрузите ZIP.`); }
    let value;
    try { if (!bytes.includes(0)) value = decoder.decode(bytes); }
    catch { /* Store the path of a non-UTF-8 file in the inventory. */ }
    if (value === undefined) {
      unreadablePaths.push(path);
      continue;
    }
    contentCount++;
    bytesRead += file.size;
    if (contentCount > 250 || bytesRead > 3000000) throw Error("Выберите до 250 текстовых файлов суммарным объёмом до 3 МБ.");
    files[path] = value;
  }
  return {files, filePaths:[...paths], unreadablePaths};
}

export async function archiveBase64(file){
  if(!file)throw Error("Выберите ZIP-архив проекта.");
  if(file.size>8000000)throw Error("ZIP превышает 8 МБ. Выберите папку одного модуля.");
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onload=()=>resolve(String(reader.result).split(",")[1]);
    reader.onerror=()=>reject(Error("Не удалось прочитать ZIP с диска."));
    reader.readAsDataURL(file);
  });
}
