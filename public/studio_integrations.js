import {telegramSettings} from "/telegram_settings.js";
import {bindGuide,installGuide} from "/model_guide.js";

export function mountIntegrations(host,{request,project,overview}){
  const canManage=overview.canManageIntegrations;
  host.innerHTML=`<details class="panel model-panel"><summary class="model-summary">
    <span class="model-heading">Модель и интеграции проекта</span><span data-profile></span></summary>
    <div class="model-content">
    ${canManage?`<form data-profile-form>
      <label class="field">Где работает модель<select name="mode">
        <option value="default">Стандартный сервер Штопки</option><option value="custom">Подключить готовый API</option>
        <option value="setup">Установить модель на свой сервер</option></select></label>
      <fieldset data-setup hidden aria-label="Установка модели">${installGuide()}</fieldset>
      <fieldset data-custom hidden><legend>Подключение к API</legend>
        <label class="field">Адрес API<input type="url" name="endpoint" placeholder="https://model.example.org/api/v1" aria-describedby="model-address-help"></label>
        <small id="model-address-help">Подойдёт базовый URL (например, /api/v1) или полный адрес /chat/completions. Адрес должен открываться с сервера Штопки.</small>
        <label class="field">Имя модели<input name="model" maxlength="128" placeholder="Имя из кабинета провайдера"></label>
        <label class="field">API-ключ<input type="password" name="apiKey" autocomplete="new-password"></label>
        <label data-clear><input name="clearKey" type="checkbox"> Удалить сохранённый ключ</label>
        <p data-pin hidden></p>
      </fieldset>
      <div class="portal-actions" data-controls><button class="button" type="button" data-probe>Проверить подключение</button>
        <button class="button primary" type="submit">Сохранить подключение</button></div>
      <p role="status" data-feedback></p><p role="alert" class="model-settings-error" hidden></p>
    </form>`:""}
    ${overview.telegramAvailable!==false&&canManage?`<section class="model-notifications"><div><h3>Уведомления</h3><p>Отчёты и действия по находкам в личном чате.</p></div><button type="button" class="button" data-tg>Настроить Telegram</button></section>`:""}
    ${canManage?"":"<p>Подключение модели и Telegram настраивает руководитель проекта.</p>"}</div></details>`;
  const describe=p=>{host.querySelector("[data-profile]").textContent=(p.custom?"Сервер проекта":"Стандартный сервер")+" · "+(p.model||"модель не настроена");};
  describe(overview.inference||{});
  const form=host.querySelector("[data-profile-form]");
  if(form){
    bindGuide(form);
    const f=form.elements, feedback=form.querySelector("[data-feedback]"), alert=form.querySelector("[role=alert]");
    let trustedEndpoint="", fingerprint="";
    function message(text,failed=false){
      feedback.textContent=failed?"":text;
      alert.textContent=failed?text:"";alert.hidden=!failed;
    }
    function toggle(){
      const custom=f.mode.value==="custom";
      form.querySelector("[data-custom]").hidden=form.querySelector("[data-custom]").disabled=!custom;
      f.endpoint.required=f.model.required=custom;
      form.querySelector("[data-setup]").hidden=form.querySelector("[data-setup]").disabled=f.mode.value!=="setup";
      form.querySelector("[data-controls]").hidden=f.mode.value==="setup";
      form.querySelector("[data-pin]").hidden=!fingerprint;
      form.querySelector("[data-pin]").textContent=fingerprint?"Сертификат проверяется по отпечатку из SSH-профиля.":"";
    }
    function fill(p){
      f.mode.value=p.custom?"custom":"default";f.endpoint.value=p.endpoint||"";f.model.value=p.custom?p.model:"";
      f.apiKey.value="";f.apiKey.placeholder=p.hasKey?"Используется сохранённый ключ":"Необязательно";
      f.clearKey.checked=false;form.querySelector("[data-clear]").hidden=!p.hasKey;
      fingerprint=p.fingerprint||"";trustedEndpoint=f.endpoint.value;toggle();
    }
    fill(overview.inference||{});
    f.mode.onchange=()=>{message("");toggle();};
    f.endpoint.addEventListener("input",()=>{
      if(fingerprint&&f.endpoint.value!==trustedEndpoint){fingerprint="";f.apiKey.value="";toggle();}
    });
    f.profileFile.onchange=async()=>{
      const file=f.profileFile.files[0];if(!file)return;
      try{
        if(file.size>20000)throw Error();
        const p=JSON.parse(await file.text());
        if(p.format!=="darning-model-v1"||typeof p.endpoint!=="string"||new URL(p.endpoint).protocol!=="https:"
          ||typeof p.model!=="string"||!/^[-\w./:@+]{1,128}$/u.test(p.model)
          ||!/^([a-f0-9]{64})$/.test(p.fingerprint)||!/^([a-f0-9]{64})$/.test(p.apiKey))throw Error();
        fill({...p,custom:true,hasKey:false});f.apiKey.value=p.apiKey;
        message("Профиль прочитан. Нажмите «Сохранить подключение», чтобы проверить модель и использовать её в проекте.");
        form.querySelector("[type=submit]").focus();
      }catch{message("Выберите JSON-файл подключения, созданный мастером Штопки.",true);}
      finally{f.profileFile.value="";}
    };
    async function apply(save){
      if(!form.reportValidity())return;
      const body={action:"inference",useDefault:f.mode.value==="default",endpoint:f.endpoint.value.trim(),
        model:f.model.value.trim(),fingerprint};
      if(f.clearKey.checked||f.apiKey.value)body.apiKey=f.clearKey.checked?"":f.apiKey.value;
      const url="/api/studio?project="+encodeURIComponent(project);
      const buttons=[...form.querySelectorAll("button")];
      const fields=[...form.querySelectorAll("input,select")];
      for(const control of [...buttons,...fields])control.disabled=true;
      form.setAttribute("aria-busy","true");
      try{
        if(!save||!body.useDefault){
          message("Проверяем ответ модели тестовым запросом…");
          await request(url,{...body,probe:true});
        }
        if(save){
          const p=await request(url,body);fill(p);describe(p);
          message(p.custom?"Модель ответила. Подключение сохранено.":"Для проекта выбран стандартный сервер.");
        }else message("Подключение работает. Модель вернула корректный ответ.");
      }catch(error){message("Ошибка подключения. "+error.message,true);}
      finally{for(const control of [...buttons,...fields])control.disabled=false;form.removeAttribute("aria-busy");}
    }
    form.onsubmit=event=>{event.preventDefault();apply(true);};
    form.querySelector("[data-probe]").onclick=()=>apply(false);
  }
  host.querySelector("[data-tg]")?.addEventListener("click",()=>telegramSettings({request,project}));
}
