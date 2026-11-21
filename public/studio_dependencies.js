export function renderDependencies(metrics,e){
  if(!metrics)return "";
  if(metrics.error)return `<section class="panel"><h3>Происхождение зависимостей</h3><p>${e(metrics.error)}</p></section>`;
  const rows=metrics.rows||[];
  const number=n=>Number.isFinite(n)?n.toLocaleString("ru-RU"):"Нет данных";
  return `<section class="panel"><h3>Происхождение зависимостей</h3><p>Проверено ${rows.length} из ${e(String(metrics.total))}. Скачивания относятся к вложениям последних десяти релизов GitHub. Просмотры доступны при разрешении владельца за 14 дней.</p><div style="overflow:auto"><table><thead><tr><th>Пакет и источник</th><th>Создан</th><th>Скачивания</th><th>Просмотры</th><th>Сигналы риска</th></tr></thead><tbody>${rows.map(r=>`<tr><td><code>${e(r.coordinate)}</code>${/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(r.repository||"")?`<br><a href="${e(r.repository)}" rel="noreferrer" target="_blank">${e(r.repository.slice(19))}</a>`:""}</td><td>${e(r.createdAt?.slice(0,10)||"Нет данных")}</td><td>${number(r.releaseDownloads)}</td><td>${number(r.views14d)}</td><td>${e((r.risks||[]).join(" ")||r.note||(r.createdAt?"Нет сигналов по возрасту и архивированию":"Недостаточно данных"))}</td></tr>`).join("")}</tbody></table></div></section>`;
}
