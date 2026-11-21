import {repositoryName} from "/source_picker.js";

export const connectionsOf = data => data.connections ?? (data.connection ? [data.connection] : []);
export const pendingsOf = data => data.pendings ?? (data.pending ? [data.pending] : []);

function copyBlock(value, label, escape) {
  return `<div class="repo-copy"><pre><code>${escape(value)}</code></pre>
    <button type="button" class="button" data-repo-copy>${label}</button></div>`;
}

export function confirmationGuide(pending, message, escape) {
  const repo = pending.repository;
  const proof = /^darning-connect ([A-Za-z0-9_-]{43})$/.exec(message || "");
  if (!proof || !/^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9_.-]{1,100}$/.test(repo) ||
      [".", ".."].includes(repo.split("/")[1])) return "";

  const url = "https://github.com/" + repo;
  const suffix = proof[1].slice(0, 12);
  const file = ".github/darning-" + suffix + ".txt";
  const folder = "darning-confirm-" + suffix;
  const clone = `git clone --depth 1 '${url}.git' '${folder}'`;
  const commit = `git -C '${folder}' commit --allow-empty -m '${message}'`;
  const push = `git -C '${folder}' push origin HEAD`;
  const windows = `${clone}\nif ($LASTEXITCODE -eq 0) {\n  ${commit}\n  if ($LASTEXITCODE -eq 0) { ${push} }\n}`;
  const unix = `${clone} &&\n${commit} &&\n${push}`;
  return `<h3>Через сайт GitHub</h3>
    <ol class="repo-steps">
      <li>Откройте <a href="${escape(url)}" target="_blank" rel="noopener">${escape(repo)} ↗</a>.
        На главной странице репозитория уже выбрана его основная ветка.</li>
      <li>Нажмите <b>Add file → Create new file</b>. Для пустого репозитория выберите <b>creating a new file</b>.
        Укажите имя нового файла ${copyBlock(file, "Скопировать имя файла", escape)}
        В содержимое впишите <code>Darning verification</code>.</li>
      <li>Нажмите <b>Commit changes…</b>. В поле <b>Commit message</b> замените предложенный заголовок этой строкой
        ${copyBlock(message, "Скопировать сообщение", escape)}
        Оставьте описание пустым, выберите запись в текущую основную ветку и нажмите <b>Commit changes</b>.</li>
    </ol>
    <details class="issue-edit repo-terminal"><summary>Через терминал с Git</summary>
      <p>Откройте терминал в папке для загрузки. Команды создадут отдельную копию репозитория и отправят пустой коммит в его основную ветку. Понадобятся настроенные в Git имя и почта, а также право записи в GitHub.</p>
      <details><summary>Windows · PowerShell</summary>${copyBlock(windows, "Скопировать команды PowerShell", escape)}</details>
      <details><summary>macOS / Linux · терминал</summary>${copyBlock(unix, "Скопировать команды терминала", escape)}</details>
    </details>
    <p>После отправки коммита вернитесь в это окно и проверьте подключение. Если для основной ветки требуется pull request, попросите администратора репозитория помочь с подтверждением. Заголовок последнего коммита в основной ветке должен совпадать с выданной строкой.</p>`;
}

export async function copyRepositoryText(button, announce) {
  const code = button.closest(".repo-copy").querySelector("code");
  try {
    await navigator.clipboard.writeText(code.textContent);
    announce("Скопировано");
  } catch {
    const range = document.createRange();
    range.selectNodeContents(code);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    announce("Текст выделен. Скопируйте его через меню браузера.");
  }
}

function installationInstructions(data, escape) {
  const installLink = data.installationUrl ? `<a class="button" href="${escape(data.installationUrl)}" target="_blank" rel="noopener">Открыть GitHub App ↗</a>`
    : "<p>Ссылку на приложение предоставит администратор «Штопки».</p>";
  return `<p>Установите GitHub App «Штопки» в аккаунт владельца репозитория или в его организацию.</p>
    ${installLink}
    <ol class="repo-steps">
      <li>В GitHub выберите аккаунт. В разделе <b>Repository access</b> выберите <b>Only select repositories</b>.</li>
      <li>Откройте <b>Select repositories</b>, добавьте нужный репозиторий и нажмите <b>Install</b>. Если GitHub предложит <b>Request</b>, дождитесь одобрения владельца организации.</li></ol>
    <details class="issue-edit"${connectionsOf(data).length ? " open" : ""}><summary>Приложение уже установлено</summary>
      <p>В <a href="https://github.com/settings/installations" target="_blank" rel="noopener">установленных приложениях GitHub</a> нажмите <b>Configure</b> рядом с приложением «Штопки». Для организации откройте её <b>Settings → GitHub Apps → Configure</b>.</p>
      <p>В разделе <b>Repository access</b> добавьте новый репозиторий к уже отмеченным и нажмите <b>Save</b>. При выборе <b>All repositories</b> доступ уже есть.</p></details>
    <p>Вернитесь в это окно после выбора репозитория в GitHub.</p>`;
}

export function openRepositorySetup({project, data, suggested, request, update, restoreFocus, escape, announce}) {
  const dialog = document.createElement("dialog");
  dialog.className = "portal-dialog repo-wizard";
  dialog.setAttribute("aria-labelledby", "repository-wizard-title");
  document.body.append(dialog);
  let name = suggested || "", busy = false;
  const match = list => list.find(item => item.repository.toLowerCase() === name.toLowerCase());
  let pending = match(pendingsOf(data));
  let stage = pending ? "confirm" : "install";
  const storeKey = () => "darning/github-confirm/" + project + "/" + name.toLowerCase();
  // The server authorizes the current manager and supplies the live challenge expiry
  // before a receipt can be restored in this tab.
  function receipt(value) {
    try {
      if (value === null) sessionStorage.removeItem(storeKey());
      else if (value) sessionStorage.setItem(storeKey(), JSON.stringify({value, expiresAt:pending.expiresAt}));
      const saved = JSON.parse(sessionStorage.getItem(storeKey()));
      return saved && saved.expiresAt === pending?.expiresAt && Date.parse(saved.expiresAt) > Date.now() ? saved.value : "";
    } catch { return ""; }
  }
  let message = pending ? receipt() : "";
  const button = (action, label, primary = false) =>
    `<button type="button" class="button${primary ? " primary" : ""}" data-wizard="${action}">${label}</button>`;
  function draw() {
    const step = {install:1, name:2, confirm:3, done:3}[stage];
    const title = {install:"Дайте приложению доступ в GitHub", name:"Выберите репозиторий", confirm:"Подтвердите доступ", done:"Репозиторий подключён"}[stage];
    const heading = `<div class="portal-dialog-header"><div><p class="fine-print">Подключение репозитория · Шаг ${step} из 3</p>
      <h2 tabindex="-1" id="repository-wizard-title">${title}</h2></div>
      <button type="button" data-wizard="close" aria-label="Закрыть окно">×</button></div>`;
    let content;
    if (stage === "install") {
      content = installationInstructions(data, escape) + `<div class="portal-actions">${button("next","Доступ выдан · продолжить",true)}</div>`;
    } else if (stage === "name") {
      content = `<form data-wizard-form><label class="field">Ссылка или имя репозитория GitHub
        <input name="repository" autocomplete="off" spellcheck="false" autocapitalize="off" required placeholder="https://github.com/owner/repository" value="${escape(name)}"></label>
        <p>Укажите репозиторий, который выбрали в настройках приложения GitHub.</p>
        <div class="portal-actions">${button("back","Назад")}<button class="button primary">Получить сообщение для коммита</button></div></form>`;
    } else if (stage === "confirm") {
      const guide = confirmationGuide(pending, message, escape);
      content = `<p><strong>${escape(name)}</strong> · сообщение действует до ${escape(new Date(pending.expiresAt).toLocaleString("ru-RU"))}.</p>
        <details class="issue-edit"><summary>Проверить доступ в GitHub App</summary>${installationInstructions(data, escape)}</details>
        ${guide || `<p>Если коммит уже отправлен, проверьте подключение. Для нового коммита получите одноразовое сообщение.</p>${button("renew","Получить новое сообщение")}`}
        <div class="portal-actions">${button("check","Проверить подключение",true)}</div>`;
    } else {
      content = `<p><strong>${escape(name)}</strong> готов к проверкам в этом проекте.</p>${button("close","К списку репозиториев",true)}`;
    }
    dialog.innerHTML = heading + `<div class="dialog-body">${content}<p role="status" data-wizard-status></p><p role="alert"></p></div>`;
    dialog.scrollTop = 0;
    const target = stage === "name" ? dialog.querySelector("input") : dialog.querySelector("h2");
    target.focus();
  }
  async function submit(action) {
    if (busy) return;
    busy = true;
    dialog.setAttribute("aria-busy","true");
    const controls = [...dialog.querySelectorAll("button:not([data-wizard=close])")];
    controls.forEach(control => { control.disabled = true; });
    dialog.querySelector("[role=alert]").textContent = "";
    dialog.querySelector("[data-wizard-status]").textContent = action === "check" ? "Проверяем подключение…" : "Получаем сообщение…";
    try {
      data = await request(action === "check" ? undefined : {action:"connect",repository:name,
        ...(action === "renew" ? {pythonPath:pending.pythonPath || "",configPath:pending.configPath || ""} : {})});
      update(data);
      const connected = match(connectionsOf(data));
      if (connected) {
        name = connected.repository; receipt(null);
        if (dialog.open) { stage = "done"; draw(); }
        return;
      }
      const previousExpiry = pending?.expiresAt;
      pending = match(pendingsOf(data));
      if (!pending) {
        receipt(null);
        if (!dialog.open) return;
        message = ""; stage = "name"; draw();
        dialog.querySelector("[role=alert]").textContent = "Срок запроса истёк или запрос отменили. Получите новое сообщение.";
        return;
      }
      name = pending.repository;
      const sameRequest = pending.expiresAt === previousExpiry;
      message = data.verificationMessage || (sameRequest && message) || receipt();
      if (data.verificationMessage) receipt(data.verificationMessage);
      if (!dialog.open) return;
      if (action === "check" && stage === "confirm") {
        if (!sameRequest) draw();
        dialog.querySelector("[data-wizard-status]").textContent = "Ожидаем коммит. Проверьте сообщение и основную ветку репозитория, затем повторите проверку.";
      } else {
        stage = "confirm"; draw();
      }
    } catch (error) {
      if (dialog.open) {
        dialog.querySelector("[data-wizard-status]").textContent = "";
        dialog.querySelector("[role=alert]").textContent = error.message;
      }
    } finally {
      busy = false;
      dialog.removeAttribute("aria-busy");
      controls.forEach(control => { control.disabled = false; });
    }
  }
  dialog.addEventListener("submit", event => {
    event.preventDefault();
    const input = event.target.elements.repository;
    name = repositoryName(input.value);
    if (!name) {
      dialog.querySelector("[role=alert]").textContent = "Введите ссылку GitHub или имя в формате владелец/репозиторий.";
      input.focus(); return;
    }
    submit("connect");
  });
  dialog.addEventListener("click", event => {
    const control = event.target.closest("button");
    if (!control) return;
    if (control.hasAttribute("data-repo-copy")) { copyRepositoryText(control, announce); return; }
    switch (control.dataset.wizard) {
      case "next": stage = "name"; draw(); break;
      case "back": name = dialog.querySelector("input").value.trim(); stage = "install"; draw(); break;
      case "close": dialog.close(); break;
      case "check": case "renew": submit(control.dataset.wizard); break;
    }
  });
  dialog.addEventListener("close", () => { dialog.remove(); restoreFocus(); }, {once:true});
  dialog.showModal();
  draw();
  return dialog;
}
