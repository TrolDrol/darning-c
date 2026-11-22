import {bindGuide,installGuide} from "/model_guide.js";

export async function openModelConnection(host,{request,url,connection,connections,onSaved}){
  const dialog=document.createElement("dialog");
  dialog.className="model-connection-dialog";
  dialog.setAttribute("aria-labelledby","model-connection-title");
  dialog.innerHTML=`<form class="model-content" data-profile-form>
    <header><h2 id="model-connection-title">Подключение модели</h2>
      <button type="button" class="studio-close" aria-label="Закрыть">×</button></header>
    <label class="field">Профиль<select name="destination">
      <option value="default">Модель проекта</option><option value="new">Новое подключение для узла</option>
    </select></label>
    <label class="field" data-connection-name hidden>Имя подключения<input name="connection" maxlength="48" pattern="[A-Za-z0-9][A-Za-z0-9_\\-]{0,47}" placeholder="Например, review-model"></label>
    <label class="field">Где работает модель<select name="mode">
      <option value="default">Стандартный сервер Штопки</option><option value="custom">Подключить готовый API</option>
      <option value="setup">Установить модель на свой сервер</option></select></label>
    <fieldset data-setup hidden aria-label="Установка модели">${installGuide()}</fieldset>
    <fieldset data-custom hidden><legend>Подключение к API</legend>
      <label class="field">Адрес API<input type="url" name="endpoint" placeholder="https://model.example.org/api/v1" aria-describedby="model-address-help"></label>
      <small id="model-address-help">Укажите базовый URL или полный адрес /chat/completions, доступный с сервера Штопки.</small>
      <label class="field">Имя модели<input name="model" maxlength="128" placeholder="Имя из кабинета провайдера"></label>
      <label class="field">API-ключ<input type="password" name="apiKey" autocomplete="new-password"></label>
      <label data-clear hidden><input name="clearKey" type="checkbox"> Удалить сохранённый ключ</label>
      <label class="field">Отпечаток TLS (SHA-256)<input name="fingerprint" maxlength="64" pattern="[a-fA-F0-9]{64}" autocomplete="off">
        <small>Для сервера с собственным сертификатом. Заполняется при импорте SSH-профиля.</small></label>
    </fieldset>
    <div class="portal-actions" data-controls><button class="button" type="button" data-probe>Проверить подключение</button>
      <button class="button primary" type="submit">Сохранить подключение</button></div>
    <p role="status" data-feedback></p><p role="alert" class="model-settings-error" hidden></p>
  </form>`;
  const form=dialog.querySelector("form"), f=form.elements;
  const feedback=form.querySelector("[data-feedback]"), alert=form.querySelector("[role=alert]");
  let trustedEndpoint="", trustedFingerprint="", hasKey=false, currentName=connection || "", checkedAt=null;
  const named=new Option(currentName,"named");
  if(currentName)f.destination.add(named,1);
  f.destination.value=currentName?"named":"default";
  dialog.querySelector(".studio-close").onclick=()=>dialog.close();
  dialog.addEventListener("close",()=>{
    dialog.remove();
    host.querySelector("[data-model-settings]")?.focus({preventScroll:true});
  },{once:true});
  host.append(dialog);dialog.showModal();
  bindGuide(form);

  function message(text,failed=false){
    feedback.textContent=failed?"":text;
    alert.textContent=failed?text:"";
    alert.hidden=!failed;
  }
  function busy(value){
    form.setAttribute("aria-busy",String(value));
    for(const control of form.querySelectorAll("input,select,button:not(.studio-close)"))control.disabled=value;
  }
  function toggle(){
    const isNew=f.destination.value==="new";
    const isDefault=f.destination.value==="default";
    if(!isDefault&&f.mode.value==="default")f.mode.value="custom";
    f.mode.options[0].disabled=!isDefault;
    form.querySelector("[data-connection-name]").hidden=!isNew;
    f.connection.required=isNew;
    const custom=f.mode.value==="custom";
    const setup=f.mode.value==="setup";
    form.querySelector("[data-custom]").hidden=form.querySelector("[data-custom]").disabled=!custom;
    f.endpoint.required=f.model.required=custom;
    form.querySelector("[data-setup]").hidden=form.querySelector("[data-setup]").disabled=!setup;
    form.querySelector("[data-controls]").hidden=setup;
    const retainKey=hasKey&&f.endpoint.value===trustedEndpoint&&f.fingerprint.value.toLowerCase()===trustedFingerprint;
    form.querySelector("[data-clear]").hidden=!retainKey;
    if(!retainKey)f.clearKey.checked=false;
    f.apiKey.placeholder=retainKey?"Используется сохранённый ключ":"Необязательно";
  }
  function fill(p){
    checkedAt=null;
    f.mode.value=p.custom?"custom":"default";
    f.endpoint.value=p.endpoint||"";
    f.model.value=p.custom?p.model:"";
    f.apiKey.value="";
    hasKey=Boolean(p.hasKey);
    f.clearKey.checked=false;
    f.fingerprint.value=trustedFingerprint=p.fingerprint||"";
    trustedEndpoint=f.endpoint.value;
    toggle();
  }
  async function load(){
    message("");
    fill({});
    if(f.destination.value==="new")return;
    const name=f.destination.value==="named"?currentName:"";
    busy(true);
    try{
      const profile=await request(url+"&modelConnection="+encodeURIComponent(name));
      fill(profile);
    }catch(error){message(error.message,true);}
    finally{busy(false);}
  }
  f.destination.onchange=load;
  f.mode.onchange=()=>{message("");toggle();};
  for(const event of ["input","change"])form.addEventListener(event,()=>{checkedAt=null;});
  f.endpoint.addEventListener("input",()=>{
    if(f.endpoint.value!==trustedEndpoint)f.fingerprint.value="";
    toggle();
  });
  f.fingerprint.addEventListener("input",toggle);
  f.profileFile.onchange=async()=>{
    const file=f.profileFile.files[0];if(!file)return;
    try{
      if(file.size>20000)throw Error();
      const p=JSON.parse(await file.text());
      if(p.format!=="darning-model-v1"||typeof p.endpoint!=="string"||new URL(p.endpoint).protocol!=="https:"
        ||typeof p.model!=="string"||!/^[-\w./:@+]{1,128}$/u.test(p.model)
        ||!/^([a-f0-9]{64})$/.test(p.fingerprint)||!/^([a-f0-9]{64})$/.test(p.apiKey))throw Error();
      fill({...p,custom:true,hasKey:false});
      f.apiKey.value=p.apiKey;
      message("Профиль прочитан. Сохраните подключение после проверки модели.");
      if(f.connection.required&&!f.connection.value)f.connection.focus();
      else form.querySelector("[type=submit]").focus();
    }catch{message("Выберите JSON-файл подключения, созданный мастером Штопки.",true);}
    finally{f.profileFile.value="";}
  };
  async function apply(save){
    if(!form.reportValidity())return;
    const isNew=f.destination.value==="new";
    const name=isNew?f.connection.value.trim():f.destination.value==="named"?currentName:"";
    if(isNew&&connections.includes(name)){
      message("Это имя уже занято. Выберите другое имя или откройте нужное подключение в узле.",true);
      return;
    }
    const body={action:"inference",useDefault:f.mode.value==="default",endpoint:f.endpoint.value.trim(),
      model:f.model.value.trim(),fingerprint:f.fingerprint.value.trim()};
    if(name)body.connection=name;
    if(f.clearKey.checked||f.apiKey.value)body.apiKey=f.clearKey.checked?"":f.apiKey.value;
    busy(true);
    try{
      const recentlyChecked=checkedAt!==null&&performance.now()-checkedAt<60_000;
      if(!save||!body.useDefault&&!recentlyChecked){
        message("Проверяем ответ модели тестовым запросом…");
        await request(url,{...body,probe:true});
        checkedAt=performance.now();
      }
      if(!save){message("Подключение работает. Модель вернула корректный ответ.");return;}
      const result=await request(url,body);
      onSaved(name);
      if(!dialog.isConnected)return;
      if(name){
        currentName=result.connection;
        named.textContent=currentName;
        if(!named.parentNode)f.destination.add(named,1);
        f.destination.value="named";
      }
      await load();
      if(alert.hidden)message(name?"Подключение сохранено и выбрано в узле.":body.useDefault?
        "Для проекта выбран стандартный сервер.":"Настройки модели проекта сохранены.");
    }catch(error){message("Ошибка подключения. "+error.message,true);}
    finally{busy(false);}
  }
  form.onsubmit=event=>{event.preventDefault();apply(true);};
  form.querySelector("[data-probe]").onclick=()=>apply(false);
  await load();
}
