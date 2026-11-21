(() => {
  const key = "darning.theme";
  const themes = [
    {id:"dark", name:"Тёмная", icon:"☾"},
    {id:"light", name:"Светлая", icon:"☀"},
    {id:"vi", name:"VI", icon:"VI"}
  ];
  function nextTheme() {
    const index = themes.findIndex(item => item.id === document.documentElement.dataset.theme);
    return themes[(index + 1) % themes.length];
  }
  function apply(theme) {
    const current = themes.find(item => item.id === theme) || themes[0];
    document.documentElement.dataset.theme = current.id;
    const label = `Тема «${current.name}». Переключить на «${nextTheme().name}»`;
    for (const button of document.querySelectorAll("[data-theme-toggle]")) {
      button.textContent = current.icon;
      button.setAttribute("aria-label", label);
      button.title = label;
    }
  }
  let initial;
  try { initial = localStorage.getItem(key); } catch {}
  apply(initial);
  document.addEventListener("DOMContentLoaded", () => apply(document.documentElement.dataset.theme));
  document.addEventListener("click", event => {
    if (!event.target.closest("[data-theme-toggle]")) return;
    const theme = nextTheme().id;
    apply(theme);
    try { localStorage.setItem(key, theme); } catch {}
  });
  window.addEventListener("storage", event => { if (event.key === key) apply(event.newValue); });
})();
