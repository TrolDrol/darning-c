const steps = {
  overview: [
    ['[href="#projects"]', "К проектам", "Здесь можно выбрать проект, подключить репозитории и пригласить участников."],
    ['[href="#projects/issues"]', "К замечаниям", "Откройте находки текущего проекта. В списке можно сменить область проверки."],
    ['[href="#analytics"]', "К аналитике", "Посмотрите, как меняется количество замечаний за выбранный период."]
  ],
  studio: [
    ['[data-automation-select]', "Выбор автоматизации", "Выберите сохранённый граф проекта. Кнопка с плюсом рядом создаёт отдельную схему."],
    ['[data-picker]', "Добавить шаг", "Откройте каталог шагов. Плюс у выхода узла сразу соединит новый шаг с графом."],
    ['[data-show-history]', "История", "Откройте запуск и выберите узел или связь на схеме, чтобы посмотреть данные."]
  ],
  projects: [
    ['.project-tabs', "Разделы проекта", "Здесь собраны репозитории, замечания и сравнение релизов."],
    ['[data-portal-action="project-invite"]', "Пригласить в проект", "Выберите роль, чтобы предоставить коллеге чтение или редактирование."]
  ],
  issues: [
    ['[data-issue-scope]', "Область замечаний", "Выберите репозиторий, проект целиком или все доступные проекты."],
    ['[data-issue-filter]', "Фильтр замечаний", "Оставьте новые, исправленные или назначенные вам замечания."]
  ],
  release: [['[data-release-repository]', "Сравнение релизов", "Выберите репозиторий и две завершённые проверки одного источника."]],
  repository: [
    ['[data-repo-add]', "Добавить репозиторий", "Мастер проведёт через установку GitHub App и подтверждение привязки."],
    ['.project-tabs', "Репозитории проекта", "В этом разделе находятся источники, подключённые к активному проекту."]
  ],
  journal: [
    ['.journal-calendar summary', "Период журнала", "Выберите даты или нажмите кнопку периода рядом."],
    ['[data-j-search]', "Поиск по событиям", "Введите название события, участника или объекта. Рядом можно выбрать категорию."],
    ['[data-j-sort="at"]', "Сортировка", "Нажмите заголовок столбца. Повторное нажатие меняет порядок."]
  ],
  analytics: [['[data-portal-control="analytics-period"]', "Период аналитики", "Выберите период, чтобы посмотреть динамику проверок и замечаний проекта."]],
  news: [
    ['[data-portal-control="news-scope"]', "Что читать", "Выберите дайджест безопасности, записи сотрудников или все публикации."],
    ['[data-portal-action="new-post"]', "Новая публикация", "Поделитесь материалом со своим предприятием. Обсуждение будет доступно его участникам."]
  ],
  profile: [['.portal-two-col .portal-tile', "Личный кабинет", "Здесь собраны ваши назначения и запуски по доступным проектам."]],
  report: [['.studio-report-heading', "Отчёт запуска", "Здесь можно скопировать ссылку на отчёт для участников проекта."]]
};

export function createPageGuide(page, replay) {
  const card = document.createElement("aside");
  card.className = "page-guide";
  card.hidden = true;
  card.setAttribute("aria-label", "Подсказки страницы");
  card.innerHTML = '<div aria-live="polite"><strong></strong><p></p></div><div class="guide-actions"><button type="button" data-dismiss>Закрыть</button><small></small><button type="button" data-next>Далее</button></div>';
  document.body.append(card);
  const memory = new Set();
  let route, key, routeIdentity, current = [], index = 0, anchor;
  let watching = false;
  const observer = new MutationObserver(tryShow);
  const visible = el => el?.getClientRects().length && !el.closest('[hidden],details:not([open]) > :not(summary)');
  function stopWatching() { observer.disconnect(); watching = false; }
  function close() {
    stopWatching();
    anchor?.classList.remove("guide-target");
    anchor = null;
    card.hidden = true;
  }
  function place() {
    if (!anchor || !anchor.isConnected || !visible(anchor)) { close(); return; }
    const r = anchor.getBoundingClientRect(), pad = 10;
    const width = document.documentElement.clientWidth, height = window.innerHeight;
    const x = Math.min(width - card.offsetWidth - pad, Math.max(pad, r.left));
    const below = r.bottom + pad;
    const y = below + card.offsetHeight < height ? below : r.top - card.offsetHeight - pad;
    card.style.left = Math.max(pad, x) + "px";
    card.style.top = Math.max(pad, Math.min(y, height - card.offsetHeight - pad)) + "px";
  }
  function showStep(manual) {
    anchor?.classList.remove("guide-target");
    const [target, title, body] = current[index];
    if (!visible(target) || !target.isConnected) { close(); return; }
    anchor = target; anchor.classList.add("guide-target");
    if (manual) anchor.scrollIntoView({block:"nearest", inline:"nearest"});
    card.querySelector("strong").textContent = title;
    card.querySelector("p").textContent = body;
    card.querySelector("small").textContent = (index + 1) + " / " + current.length;
    card.querySelector("[data-next]").textContent = index + 1 < current.length ? "Далее" : "Готово";
    card.hidden = false; place();
    if (manual) card.querySelector("[data-next]").focus({preventScroll:true});
  }
  function tryShow() {
    if (!watching || !page.isConnected || page.getAttribute("aria-busy") === "true") return;
    if (document.querySelector("dialog[open]")) { stopWatching(); return; }
    current = steps[route].map(([selector, ...text]) => [[...page.querySelectorAll(selector)].find(visible), ...text]).filter(([el]) => el);
    if (!current.length) return;
    stopWatching(); index = 0; memory.add(key);
    try { localStorage.setItem(key, "1"); } catch { /* session memory still works */ }
    showStep(document.activeElement === replay);
  }
  function start() {
    if (!key) return;
    close(); watching = true;
    observer.observe(page, {childList:true, subtree:true, attributes:true, attributeFilter:["aria-busy"]});
    requestAnimationFrame(tryShow);
  }
  card.querySelector("[data-next]").onclick = () => {
    if (++index < current.length) showStep(true);
    else { close(); replay.focus({preventScroll:true}); }
  };
  card.querySelector("[data-dismiss]").onclick = () => { close(); replay.focus({preventScroll:true}); };
  replay.onclick = start;
  document.addEventListener("pointerdown", e => {
    if (!card.hidden && !card.contains(e.target) && !replay.contains(e.target)) close();
  }, true);
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !card.hidden) {
      const restore = card.contains(document.activeElement);
      close(); if (restore) replay.focus({preventScroll:true});
    }
  });
  window.addEventListener("resize", () => { if (!card.hidden) place(); });
  window.addEventListener("scroll", () => { if (!card.hidden) place(); }, true);
  return {visit(view, username, detail) {
    const identity = JSON.stringify([view, username, detail]);
    if (identity === routeIdentity) return;
    routeIdentity = identity; close(); route = view;
    key = username && steps[view] ? "darning.guide.1." + JSON.stringify([username, view]) : "";
    replay.hidden = !key;
    if (!key || memory.has(key)) return;
    try { if (localStorage.getItem(key)) return; } catch { /* storage disabled */ }
    start();
  }};
}
