export function discussion(host,project,run,index,request) {
  const finding=run.findings[index];
  const dialog=document.createElement("dialog");
  dialog.className="studio-dialog studio-discussion";
  dialog.setAttribute("aria-label","Обсудить замечание");
  dialog.innerHTML=`<header class="studio-discussion-head"><h2>Обсудить замечание</h2>
    <button type="button" class="studio-close" aria-label="Закрыть">×</button></header>
    <form class="studio-dialog-form"><strong data-location></strong>
      <p>Модель проекта получает характеристики замечания и переписку. Ответы модели требуют проверки. История доступна до закрытия окна.</p>
      <div role="log" aria-live="polite"></div>
      <label class="field">Ваш вопрос<textarea required maxlength="1600" rows="3"></textarea></label>
      <p role="alert" class="run-error"></p><button type="submit" class="button primary">Отправить</button>
    </form>`;
  dialog.querySelector(".studio-close").onclick=()=>dialog.close();
  dialog.addEventListener("close",()=>dialog.remove(),{once:true});
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
    finally{input.disabled=button.disabled=turns.length>=10;if(dialog.open && !input.disabled)input.focus();}
  };
  host.append(dialog);
  dialog.showModal();
}
