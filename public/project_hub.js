const sections = [
  ["projects", "Участники", "#projects"],
  ["repository", "Репозитории", "#projects/repositories"],
  ["issues", "Замечания", "#projects/issues"],
  ["journal", "Журнал", "#projects/journal"],
  ["release", "Сравнение релизов", "#projects/releases"],
  ["analytics", "Аналитика", "#projects/analytics"]
];

let projects = [];
export function setProjectChoices(choices) {
  projects = choices;
}

export function projectTabs(active, projectId) {
  const visible = sections.filter(([key]) => projectId || ["projects", "issues"].includes(key));
  const options = projects.map(item => new Option(item.name + " · " + item.organizationName, item.id, item.id === projectId).outerHTML);
  const picker = options.length ? `<label class="project-picker"><span class="visually-hidden">Активный проект</span><select id="project-switcher"><button type="button"><selectedcontent></selectedcontent></button><option disabled value="" ${projectId ? "" : "selected"}>Выберите проект</option>${options.join("")}</select></label>` : "";
  return '<div class="project-nav-row"><nav class="project-tabs" aria-label="Разделы проектов">' + visible.map(([key, label, href]) =>
    `<a href="${!projectId && key === "issues" ? href + "?scope=all" : href}"${key === active ? ' aria-current="page"' : ""}>${label}</a>`
  ).join("") + "</nav>" + picker + "</div>";
}

export function projectRoute(section, detail = "", params = {}) {
  const suffix = new URLSearchParams(Object.entries(params).filter(([, value]) => value)).toString();
  return "#projects/" + section + (detail ? "/" + encodeURIComponent(detail) : "") + (suffix ? "?" + suffix : "");
}
export const severityLabels = {low: "Низкая", medium: "Средняя", high: "Высокая", critical: "Критическая"};
