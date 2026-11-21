// Port keys are part of the published graph and the run trace.
export const portNames = {
  in:"Поток", next:"Далее", true:"Да", false:"Нет", paths:"Пути файлов",
  values:"Строки", count:"Количество", matches:"Совпадения", found:"Найдено"
};
export const portTypes = {
  in:"flow", next:"flow", true:"flow", false:"flow", paths:"strings",
  values:"strings", count:"int", matches:"strings", found:"bool"
};
export const typeNames = {flow:"Поток", strings:"Список строк", int:"Целое число", bool:"Да / нет"};
export function outputPorts(type) {
  if (type === "source") return ["next","paths"];
  if (type === "regex") return ["count","matches","found"];
  if (type === "condition") return ["true","false"];
  return ["next"];
}
export function inputPorts(type) {
  if (type === "manual" || type === "schedule") return [];
  if (type === "regex") return ["in","values"];
  if (type === "condition") return ["in","count","found"];
  return ["in"];
}
