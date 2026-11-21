const operations = {
  trim:"Убрать пробелы по краям", lower:"Перевести в нижний регистр", unique:"Убрать повторы",
  contains:"Содержит текст", prefix:"Начинается с", suffix:"Заканчивается на"
};
const needsText = op => ["contains","prefix","suffix"].includes(op);
export const customDefaults = () => ({name:"Моя обработка",steps:[{op:"unique"}],values:[]});

export function customFields(params, e, disabled) {
  const rows = params.steps.map((step,index) => `<div class="field">
    <label>Операция ${index+1}<select data-step-op="${index}" ${disabled}>
      ${Object.entries(operations).map(([key,label])=>`<option value="${key}" ${key===step.op?"selected":""}>${label}</option>`).join("")}</select></label>
    ${needsText(step.op)?`<input aria-label="Текст операции ${index+1}" data-step-text="${index}" value="${e(step.text)}" maxlength="256" ${disabled}>`:""}
    ${!disabled && params.steps.length>1?`<button type="button" class="link-button" data-drop-step="${index}">Убрать операцию</button>`:""}</div>`).join("");
  return `<label class="field">Название ноды<input maxlength="60" data-param="name" value="${e(params.name)}" ${disabled}></label>
    ${rows}${!disabled && params.steps.length<12?'<button type="button" class="button" data-new-step>Добавить операцию</button>':""}
    <button type="button" class="link-button" data-download-node>Скачать определение</button>
    ${!disabled?'<label class="field">Загрузить определение ноды<input type="file" accept="application/json,.json" data-import-node></label>':""}`;
}

export function exportDefinition(params) {
  const definition = {format:"darning.node",version:1,name:params.name,steps:params.steps};
  const url=URL.createObjectURL(new Blob([JSON.stringify(definition,null,2)],{type:"application/json"}));
  const link=document.createElement("a");
  link.href=url; link.download="darning-node.json"; link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export async function importDefinition(file) {
  if (!file || file.size>32768) throw Error("Выберите JSON-файл определения до 32 КБ.");
  const data=JSON.parse(await file.text());
  if (data?.format!=="darning.node" || data.version!==1 || typeof data.name!=="string" || !data.name.trim() || data.name.length>60 ||
      !Array.isArray(data.steps) || !data.steps.length || data.steps.length>12 ||
      !data.steps.every(s=>s && typeof s.op==="string" && Object.hasOwn(operations,s.op) && (!needsText(s.op) || typeof s.text==="string" && s.text.length>0 && s.text.length<=256)))
    throw Error("Проверьте формат определения, название и операции.");
  return {name:data.name.trim(),steps:data.steps.map(s=>needsText(s.op)?{op:s.op,text:s.text}:{op:s.op})};
}

export function changeStep(params, el) {
  if (el.hasAttribute("data-new-step") && params.steps.length<12) params.steps.push({op:"unique"});
  else if (el.hasAttribute("data-drop-step") && params.steps.length>1) params.steps.splice(Number(el.dataset.dropStep),1);
  else if (el.hasAttribute("data-step-op")) params.steps[Number(el.dataset.stepOp)]=needsText(el.value)?{op:el.value,text:""}:{op:el.value};
  else if (el.hasAttribute("data-step-text")) params.steps[Number(el.dataset.stepText)].text=el.value;
}
