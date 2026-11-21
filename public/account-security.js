const byId = id => document.getElementById(id);

async function api(path, data) {
  const headers = {"X-Workspace-Session": "1"};
  const options = {headers, credentials:"same-origin", cache:"no-store"};
  if (data !== undefined) {
    headers["Content-Type"] = "application/json";
    Object.assign(options, {method:"POST", body:JSON.stringify(data)});
  }
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw Error(body.error || "Не удалось выполнить запрос.");
  return body;
}

function recovery() {
  document.title = "Восстановление пароля · Штопка";
  byId("recover").hidden = false;
  let token = location.hash.slice(1);
  if (token) history.replaceState(null, "", location.pathname);
  const form = byId(token ? "complete-reset" : "request-reset");
  byId("request-reset").hidden = Boolean(token);
  form.hidden = false;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const status = byId("recovery-status");
    const button = form.querySelector("button");
    if (button.disabled) return;
    if (token && form.elements.password.value !== form.elements.repeat.value) {
      status.textContent = "Пароли не совпадают."; form.elements.repeat.focus(); return;
    }
    button.disabled = true;
    status.textContent = "";
    try {
      if (token) {
        await api("/api/recovery/complete", {token, password:form.elements.password.value});
        token = "";
        status.textContent = "Пароль сохранён. Теперь войдите с новым паролем.";
      } else {
        await api("/api/recovery/request", {username:form.elements.username.value.trim()});
        status.textContent = "Если к этому логину привязана подтверждённая почта, письмо придёт на неё. Ссылка действует 20 минут.";
      }
      form.reset(); form.hidden = true;
    } catch (error) {status.textContent = error.message;}
    finally {button.disabled = false;}
  });
}

function directory() {
  document.title = "Пользователи · Штопка";
  byId("directory").hidden = false;
  const modal = byId("manage"), form = byId("action-form");
  const more = byId("more"), apply = byId("apply"), close = byId("close");
  let next = null, target, action, row;
  close.onclick = () => modal.close();
  modal.addEventListener("cancel", event => { if (close.disabled) event.preventDefault(); });
  modal.addEventListener("close", () => { form.reset(); });
  function show(user, operation, tr) {
    target = user.username; row = tr; action = operation;
    const deleting = action === "delete";
    byId("manage-title").textContent = deleting ? "Удаление пользователя" : "Восстановление пароля";
    byId("instructions").textContent = deleting
      ? `У пользователя ${target} будут удалены контакты и доступы. История действий сохранится. Введите его логин.`
      : `Проверьте личность пользователя ${target}. Затем создайте ссылку и передайте её пользователю лично.`;
    byId("action-status").textContent = "";
    byId("confirm-label").hidden = !deleting;
    form.elements.confirmation.required = deleting;
    byId("link-label").hidden = true;
    apply.hidden = false;
    apply.className = deleting ? "button danger" : "button primary";
    apply.textContent = deleting ? "Удалить пользователя" : "Создать ссылку";
    modal.showModal();
    if (deleting) form.elements.confirmation.focus();
  }
  form.onsubmit = async event => {
    event.preventDefault();
    if (apply.disabled) return;
    if (action === "delete" && form.elements.confirmation.value !== target) {
      byId("action-status").textContent = "Логин не совпадает."; return;
    }
    apply.disabled = close.disabled = true;
    try {
      const data = await api("/api/admin/users", {action, username:target, confirmation:form.elements.confirmation.value});
      if (action === "delete") {
        row.remove(); modal.close(); byId("directory-status").textContent = "Доступ пользователя удалён.";
      } else {
        form.elements.url.value = data.url;
        byId("link-label").hidden = false;
        byId("instructions").textContent = "Ссылка действует 20 минут и позволяет один раз задать новый пароль.";
        apply.hidden = true; form.elements.url.select(); byId("action-status").textContent = "";
      }
    } catch (error) {byId("action-status").textContent = error.message;}
    finally {apply.disabled = close.disabled = false;}
  };
  function add(user) {
    const tr = byId("people").insertRow();
    const name = tr.insertCell();
    const strong = document.createElement("strong"), login = document.createElement("small");
    strong.textContent = user.displayName; login.textContent = user.username; name.append(strong, login);
    tr.insertCell().textContent = user.email || "—";
    const tg = tr.insertCell();
    for (const chat of user.telegram) {
      const line = document.createElement("div"); line.textContent = `${chat.project} · ${chat.chatId}`; tg.append(line);
    }
    if (!user.telegram.length) tg.textContent = "—";
    const access = tr.insertCell();
    if (user.system) {
      access.textContent = user.role === "super_admin" ? "Супер-администратор" : "Служебная учётная запись";
      return;
    }
    const actions = document.createElement("div"); actions.className = "account-actions"; access.append(actions);
    for (const [op, caption] of [["reset","Сброс пароля"],["delete","Удалить"]]) {
      const button = document.createElement("button");
      button.type = "button"; button.className = op === "delete" ? "button danger" : "button";
      button.textContent = caption; button.onclick = () => show(user, op, tr); actions.append(button);
    }
  }
  async function load() {
    more.disabled = true;
    try {
      const data = await api("/api/admin/users" + (next ? "?after=" + encodeURIComponent(next) : ""));
      data.users.forEach(add);
      next = data.next; more.hidden = !next; more.textContent = "Ещё пользователи";
      byId("directory-status").textContent = "";
    } catch (error) {
      byId("directory-status").textContent = error.message; more.hidden = false; more.textContent = "Повторить";
    } finally {more.disabled = false;}
  }
  more.onclick = load;
  load();
}

if (location.pathname === "/admin") directory();
else recovery();
