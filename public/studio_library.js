export function libraryMarkup(writable, publishable) {
  return `<h2>Библиотека сценариев</h2>
    <label class="field">Коллекция<select data-library-scope><option value="community">Общая библиотека</option>
    <option value="organization">Моё предприятие</option></select></label>
    <div data-library-items aria-live="polite"></div>
    <div class="portal-actions">
      ${publishable?'<button class="button" type="button" data-modal="template">Опубликовать свой сценарий</button>':""}
      ${writable?'<button class="button" type="button" data-import-file>Импортировать JSON</button><input hidden type="file" data-library-file accept=".json,application/json">':""}
    </div>`;
}

export function mountLibrary(form, {url, projectUrl, request, escape:e, writable, scope, openCopy}) {
  const selector = form.querySelector("[data-library-scope]");
  const list = form.querySelector("[data-library-items]");
  const error = form.querySelector('[role="alert"]');
  let revision = 0, pending = false;
  selector.value = scope || "community";
  const address = params => url + "&" + new URLSearchParams({scope:selector.value, ...params});
  function active() { return form.isConnected && form.closest("dialog")?.open; }
  async function browse(offset = 0) {
    const read = ++revision;
    list.textContent = "Загружаем сценарии…";
    error.textContent = "";
    try {
      const result = await request(address({offset}));
      if(!active() || read !== revision) return;
      list.innerHTML = (result.items.length ? `<ul class="studio-library">${result.items.map(item =>
        `<li><strong>${e(item.name)}</strong><p>${e(item.description)}</p><div class="portal-actions">
        ${writable?`<button class="button" type="button" data-library-use="${e(item.id)}">Использовать</button>`:""}
        <button class="link-button" type="button" data-library-download="${e(item.id)}">Скачать JSON</button></div></li>`).join("")}</ul>` :
        "<p>В этой коллекции пока нет опубликованных сценариев.</p>") +
        `<div class="portal-actions">${offset?`<button type="button" class="button" data-library-offset="${Math.max(0,offset-20)}">Назад</button>`:""}
        ${result.nextOffset!=null?`<button type="button" class="button" data-library-offset="${result.nextOffset}">Далее</button>`:""}</div>`;
    } catch (err) {
      if(active() && read === revision) {
        error.textContent = err.message;
        list.innerHTML = '<button type="button" class="button" data-library-offset="0">Повторить загрузку</button>';
      }
    }
  }
  async function use(data) {
    const copy = await request(projectUrl, {action:"library_import", ...data});
    if(active()) openCopy(copy);
  }
  async function perform(task, button) {
    if(pending) return;
    pending = true;
    if(button) button.disabled = true;
    selector.disabled = true;
    error.textContent = "";
    try { await task(); }
    catch(err) { if(active()) error.textContent = err.message; }
    finally { pending = false; selector.disabled = false; if(button) button.disabled = false; }
  }
  selector.addEventListener("change", ()=>browse());
  const file = form.querySelector("[data-library-file]");
  file?.addEventListener("change", () => perform(async () => {
    const item = file.files[0]; file.value = "";
    if(!item) return;
    if(item.size > 262144) throw Error("Выберите JSON-файл шаблона размером до 256 КБ.");
    let document;
    try { document = JSON.parse(await item.text()); }
    catch { throw Error("Не удалось прочитать JSON. Скачайте шаблон ещё раз."); }
    await use({document});
  }, form.querySelector("[data-import-file]")));
  form.addEventListener("click", event => {
    const button = event.target.closest("button");
    if(!button || pending) return;
    if(button.hasAttribute("data-import-file")) { file.click(); return; }
    if(button.hasAttribute("data-library-offset")) { browse(Number(button.dataset.libraryOffset)); return; }
    if(button.hasAttribute("data-library-use")) {
      perform(()=>use({scope:selector.value, id:button.dataset.libraryUse}), button);
    } else if(button.hasAttribute("data-library-download")) {
      perform(async ()=>{
        const doc = await request(address({id:button.dataset.libraryDownload}));
        if(!active()) return;
        const href = URL.createObjectURL(new Blob([JSON.stringify(doc,null,2)+"\n"], {type:"application/json"}));
        const link = document.createElement("a");
        link.href = href; link.download = "darning-workflow-" + button.dataset.libraryDownload + ".json";
        link.click(); setTimeout(()=>URL.revokeObjectURL(href),1000);
      }, button);
    }
  });
  browse();
}
