export async function telegramSettings({request,project}) {
  const dialog=document.createElement("dialog");
  dialog.className="studio-dialog telegram-settings";
  dialog.setAttribute("aria-labelledby","tg-settings-heading");
  dialog.innerHTML=`<form class="studio-dialog-form">
    <h2 id="tg-settings-heading">Telegram проекта</h2>
    <p data-info role="status">Проверяем подключение…</p>
    <p data-success role="status" hidden></p>
    <p data-error class="run-error" role="alert"></p>
    <a class="button" data-link target="_blank" rel="noopener noreferrer" hidden>Открыть бота в Telegram</a>
    <div data-confirm-step hidden><label class="field">Код от бота
      <input name="code" inputmode="numeric" pattern="[0-9]{8}" maxlength="8" autocomplete="one-time-code">
    </label></div>
    <div class="portal-actions">
      <button class="button primary" data-connect type="button" hidden>Открыть Telegram</button>
      <button class="button primary" data-confirm type="submit" hidden>Подтвердить код</button>
      <button class="button" data-disconnect type="button" hidden>Отключить чат</button>
      <button class="button" data-close type="button">Закрыть</button>
    </div></form>`;
  document.body.append(dialog);
  const el=selector=>dialog.querySelector(selector);
  const endpoint="/api/telegram?"+new URLSearchParams({project});
  const form=el("form"), code=form.elements.code;
  let state, startUrl="", timer, revision=0, busy=false;

  function draw() {
    const {configured,canManage,connected,own,pairing,awaitingCode}=state;
    const waiting=pairing&&!awaitingCode;
    el("[data-info]").textContent=!configured?"Администратору нужно настроить Telegram-бота проекта."
      :awaitingCode?"Бот выдал код. Введите здесь восемь цифр из личного чата."
      :waiting?"В личном чате нажмите Start («Запустить»). Бот пришлёт код. Вернитесь на эту страницу в течение 10 минут."
      :connected?"":"В личном чате бот «Штопки» присылает результаты проверок. Откройте Telegram, нажмите Start и вернитесь на сайт с кодом.";
    el("[data-info]").hidden=!el("[data-info]").textContent;
    const success=el("[data-success]");
    success.hidden=!connected||pairing;
    success.textContent=own?"✓ Ваш личный чат подключён. Отчёты проекта будут приходить в Telegram.":"✓ Telegram подключён. Для проекта назначен получатель.";
    el("[data-connect]").hidden=!configured||!canManage;
    el("[data-connect]").textContent=pairing?"Начать заново":connected?"Сменить получателя":"Открыть Telegram";
    el("[data-disconnect]").hidden=!connected||!canManage||pairing;
    el("[data-link]").hidden=!waiting||!startUrl;
    if(startUrl)el("[data-link]").href=startUrl;
    el("[data-confirm-step]").hidden=el("[data-confirm]").hidden=!awaitingCode;
    code.disabled=!awaitingCode;code.required=awaitingCode;
    if(!awaitingCode)code.value="";
  }
  function observe() {
    clearTimeout(timer);
    if(dialog.open&&state?.pairing&&!document.hidden)timer=setTimeout(refresh,3000);
  }
  async function refresh() {
    if(busy||!dialog.open)return;
    clearTimeout(timer);
    const current=++revision;
    try{
      const next=await request(endpoint);
      if(current!==revision||!dialog.open)return;
      const expired=state?.pairing&&!next.pairing&&!next.connected;
      const received=!state?.awaitingCode&&next.awaitingCode;
      if(expired){startUrl="";el("[data-error]").textContent="Срок привязки истёк. Откройте Telegram ещё раз, чтобы получить новый код.";}
      state=next;draw();
      if(received&&!document.hidden)code.focus();
    }catch(error){if(current===revision)el("[data-error]").textContent=error.message;}
    finally{if(current===revision)observe();}
  }
  async function act(action) {
    if(busy)return;
    busy=true;++revision;clearTimeout(timer);
    el("[data-error]").textContent="";
    let tab;
    if(action==="connect"){
      // Keep the user's navigation gesture when requesting a single-use /start link.
      tab=window.open("about:blank","_blank");
      if(tab)tab.opener=null;
    }
    const buttons=form.querySelectorAll("button:not([data-close])");
    buttons.forEach(button=>button.disabled=true);
    try{
      const reply=await request(endpoint,action==="confirm"?{action,code:code.value}:{action});
      if(!dialog.open){tab?.close();return;}
      if(action==="connect"){
        const link=new URL(reply.url);
        if(link.origin!=="https://t.me")throw Error("Не удалось получить ссылку на бота.");
        startUrl=link.href;
        state={...state,pairing:true,awaitingCode:false};
        if(tab)tab.location.replace(startUrl);
      }else{startUrl="";state=reply;code.value="";}
      draw();
    }catch(error){
      tab?.close();
      el("[data-error]").textContent=error.message;
      if(action==="confirm"){
        code.value="";
        if(code.isConnected)code.focus();
      }
    }finally{
      busy=false;buttons.forEach(button=>button.disabled=false);
      if(action==="confirm"&&state?.pairing)await refresh();
      else observe();
    }
  }
  function onReturn(){if(!document.hidden&&state?.pairing)refresh();}
  el("[data-connect]").onclick=()=>act("connect");
  el("[data-disconnect]").onclick=()=>act("disconnect");
  form.onsubmit=event=>{event.preventDefault();if(state?.awaitingCode)act("confirm");};
  el("[data-close]").onclick=()=>dialog.close();
  window.addEventListener("focus",onReturn);
  document.addEventListener("visibilitychange",onReturn);
  dialog.addEventListener("close",()=>{
    clearTimeout(timer);++revision;
    window.removeEventListener("focus",onReturn);
    document.removeEventListener("visibilitychange",onReturn);
    dialog.remove();
  },{once:true});
  dialog.showModal();await refresh();
}
