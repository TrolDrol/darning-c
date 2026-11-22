// Port keys are part of the published graph and the run trace.
export const portNames = {
  in:"Поток", next:"Далее", true:"Да", false:"Нет", paths:"Пути файлов",
  values:"Строки", count:"Количество", matches:"Совпадения", found:"Найдено", model:"Модель"
};
export const portTypes = {
  in:"flow", next:"flow", true:"flow", false:"flow", paths:"strings",
  values:"strings", count:"int", matches:"strings", found:"bool", model:"model"
};
export const typeNames = {flow:"Поток", strings:"Список строк", int:"Целое число", bool:"Да / нет", model:"Подключение к модели"};
export function modelPortLabel(reference) {
  return [portNames.model,reference.connection || "Подключение проекта",reference.model].filter(Boolean).join(" · ");
}
export const triggerTypes = ["manual", "schedule", "github_pr", "github_push", "webhook"];
export function outputPorts(type) {
  if (type === "source") return ["next","paths"];
  if (type === "model_load") return ["model"];
  if (["regex","custom"].includes(type)) return ["count","matches","found"];
  if (type === "condition") return ["true","false"];
  return ["next"];
}
export function inputPorts(type) {
  if (triggerTypes.includes(type)) return [];
  if (["explain","ai_review"].includes(type)) return ["in","model"];
  if (["regex","custom"].includes(type)) return ["in","values"];
  if (type === "condition") return ["in","count","found"];
  return ["in"];
}
