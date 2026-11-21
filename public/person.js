const escape = value => String(value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));

export function personMarkup(displayName, avatar) {
  const name = String(displayName || "Система");
  const initials = name.trim().split(/\s+/u).slice(0,2).map(word=>Array.from(word)[0]).join("").toLocaleUpperCase("ru");
  const photo = typeof avatar === "string" && /^data:image\/png;base64,[a-z0-9+/]+=*$/i.test(avatar)
    ? `<img class="person-avatar" alt="" width="28" height="28" src="${escape(avatar)}">`
    : `<span class="person-avatar" aria-hidden="true">${escape(initials)}</span>`;
  return `<span class="person-label">${photo}<span>${escape(name)}</span></span>`;
}
