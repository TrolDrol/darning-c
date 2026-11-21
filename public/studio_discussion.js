function modal(host, title, fields, submitLabel) {
  const dialog=document.createElement("dialog");
  dialog.className="studio-dialog";
  dialog.setAttribute("aria-label",title);
  dialog.innerHTML=`<form class="studio-dialog-form"><button type="button" class="studio-close" aria-label="Закрыть">×</button>
    <h2></h2>${fields}<p role="alert"></p><button type="submit" class="button primary"></button></form>`;
  dialog.querySelector("h2").textContent=title;
  dialog.querySelector("[type=submit]").textContent=submitLabel;
  dialog.querySelector(".studio-close").onclick=()=>dialog.close();
  dialog.addEventListener("close",()=>dialog.remove(),{once:true});
  host.append(dialog);
  dialog.showModal();
  return dialog;
}

export function modelDialog(host,request,url,saved) {
  const dialog=modal(host,"Подключение модели",`
    <label class="field">Имя подключения<input name="connection" pattern="[A-Za-z0-9][A-Za-z0-9_\\-]{0,47}" required></label>
    <label class="field">Адрес API<input type="url" name="endpoint" required></label>
    <label class="field">ID модели<input name="model" required maxlength="128"></label>
    <label class="field">API-ключ<input type="password" name="apiKey" autocomplete="new-password"></label>
    <label class="field">SHA-256 сертификата для своего сервера<input name="fingerprint" maxlength="64"></label>
    <small>Повторное сохранение под тем же именем обновит подключение для использующих его блоков. Пустой ключ сохраняет прежний ключ того же сервера.</small>`,"Сохранить подключение");
  dialog.querySelector("form").onsubmit=async event=>{
    event.preventDefault();
    const values=Object.fromEntries(new FormData(event.target));
    if(!values.apiKey)delete values.apiKey;
    if(!values.fingerprint)delete values.fingerprint;
    const button=dialog.querySelector("[type=submit]");
    button.disabled=true;
    try {
      const result=await request(url,{action:"inference",...values});
      if(dialog.isConnected){saved(result.connection);dialog.close();}
    }catch(error){dialog.querySelector("[role=alert]").textContent=error.message;}
    finally{button.disabled=false;}
  };
}

export function discussion(host,project,run,index,request) {
  const finding=run.findings[index];
  const dialog=modal(host,"Обсудить замечание",`<strong data-location></strong>
    <p>Модель проекта получает характеристики замечания и переписку. Ответы модели требуют проверки. История доступна до закрытия окна.</p>
    <div aria-live="polite" role="log"></div><label class="field">Ваш вопрос<textarea required maxlength="1600" rows="3"></textarea></label>`,"Отправить");
  dialog.querySelector("[data-location]").textContent=[finding.title || finding.class,finding.path,finding.line].filter(Boolean).join(" · ");
  const input=dialog.querySelector("textarea"), log=dialog.querySelector("[role=log]"), button=dialog.querySelector("[type=submit]");
  const turns=[];
  dialog.querySelector("form").onsubmit=async event=>{
    event.preventDefault();
    if(button.disabled || !input.value.trim())return;
    const question={role:"user",text:input.value.trim()};
    input.disabled=button.disabled=true;
    const notice=dialog.querySelector("[role=alert]");
    notice.textContent="Модель готовит ответ…";
    try{
      const data=await request("/api/studio/discuss?project="+encodeURIComponent(project),{runId:run.id,finding:index,findingKey:finding.discussionKey,messages:[...turns,question]});
      turns.push(question,{role:"assistant",text:data.answer});
      for(const [name,message] of [["Вы",question.text],[data.model,data.answer]]){
        const by=document.createElement("strong"), p=document.createElement("p");
        by.textContent=name;p.textContent=message;log.append(by,p);
      }
      input.value="";
      notice.textContent=turns.length>=10?"Чтобы продолжить, откройте новое обсуждение.":"";
    }catch(error){notice.textContent=error.message;}
    finally{input.disabled=button.disabled=turns.length>=10;if(!input.disabled)input.focus();}
  };
}
