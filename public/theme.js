(() => {
  const key = "darning.theme";
  const moon = '<path d="M20.7 14.1A8.8 8.8 0 0 1 9.9 3.3a9 9 0 1 0 10.8 10.8Z"/>';
  const sun = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>';
  function lineIcon(shape) {
    return `<svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${shape}</svg>`;
  }
  const themes = [
    {id:"dark", name:"Тёмная", icon:lineIcon(moon)},
    {id:"light", name:"Светлая", icon:lineIcon(sun)},
    {id:"vi", name:"VI", icon:'<img src="/darning-swap-theme.png" width="26" height="26" alt="">'}
  ];
  function nextTheme() {
    const index = themes.findIndex(item => item.id === document.documentElement.dataset.theme);
    return themes[(index + 1) % themes.length];
  }
  function apply(theme) {
    const current = themes.find(item => item.id === theme) || themes[0];
    document.documentElement.dataset.theme = current.id;
    for (const logo of document.querySelectorAll(".masthead .brand img")) {
      const src = current.id === "vi" ? "/darning-logo-2.png" : "/darning-logo.png";
      if (logo.getAttribute("src") !== src) logo.src = src;
    }
    const label = `Тема «${current.name}». Переключить на «${nextTheme().name}»`;
    for (const button of document.querySelectorAll("[data-theme-toggle]")) {
      if (button.dataset.themeIcon !== current.id) {
        button.innerHTML = current.icon;
        button.dataset.themeIcon = current.id;
      }
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
