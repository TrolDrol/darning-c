export async function emailSettings(request) {
  const dialog = document.createElement("dialog");
  dialog.className = "studio-dialog";
  dialog.setAttribute("aria-labelledby","email-heading");
  dialog.innerHTML = `<div class="studio-dialog-form"><h2 id="email-heading">Почта профиля</h2>
    <p data-status role="status">Загрузка…</p>
    <form data-address hidden><label class="field">Электронная почта
      <input type="email" name="email" maxlength="254" autocomplete="email" required></label>
      <button type="submit" class="button">Получить код</button></form>
    <form data-confirm hidden><label class="field">Код из письма
      <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="8" pattern="[0-9]{8}" required></label>
      <button type="submit" class="button primary">Подтвердить почту</button></form>
    <p data-error class="run-error" role="alert"></p><div class="portal-actions">
      <button type="button" class="button" data-disconnect hidden>Отвязать почту</button>
      <button type="button" class="button" data-close>Закрыть</button></div></div>`;
  document.body.append(dialog);
  const find = selector => dialog.querySelector(selector);
  const address = find("[data-address]"), confirm = find("[data-confirm]");
  const submit = dialog.querySelectorAll("button:not([data-close])");
  let timer, loading = false;
  function render(state) {
    const messages = [];
    if (state.email) messages.push("Подтверждённая почта: " + state.email + ".");
    if (state.state === "queued") messages.push("Отправляем код на " + state.pending + ".");
    if (state.state === "sent") messages.push("Введите код из письма на " + state.pending + ".");
    if (state.state === "failed") messages.push("Сервер отклонил письмо. Проверьте адрес и запросите код снова.");
    if (!state.configured) messages.push("Для отправки кода администратору нужно настроить SMTP.");
    if (!messages.length) messages.push("Введите адрес и подтвердите его кодом из письма.");
    find("[data-status]").textContent = messages.join(" ");
    address.hidden = !state.configured;
    confirm.hidden = state.state !== "sent";
    find("[data-disconnect]").hidden = !state.email && !state.pending;
    if (state.state === "queued") timer = setTimeout(() => update(),2000);
  }
  async function update(payload) {
    if (loading || !dialog.open) return;
    clearTimeout(timer);
    loading = true;
    for (const button of submit) button.disabled = true;
    find("[data-error]").textContent = "";
    try {
      const state = await request("/api/account/email",payload);
      if (dialog.open) render(state);
      if (payload) confirm.reset();
    } catch (error) { find("[data-error]").textContent = error.message; }
    finally { for (const button of submit) button.disabled = false; loading = false; }
  }
  address.onsubmit = event => { event.preventDefault(); update({action:"request",email:address.elements.email.value}); };
  confirm.onsubmit = event => { event.preventDefault(); update({action:"confirm",code:confirm.elements.code.value}); };
  find("[data-disconnect]").onclick = () => update({action:"disconnect"});
  find("[data-close]").onclick = () => dialog.close();
  dialog.addEventListener("close", () => {
    clearTimeout(timer);
    dialog.remove();
    document.querySelector("#account-menu-toggle")?.focus();
  },{once:true});
  dialog.showModal();
  await update();
}
