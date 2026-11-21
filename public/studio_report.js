import {renderDependencies} from "/studio_dependencies.js";

export function reportMarkup(run,e,labels) {
  const state={queued:"В очереди",running:"Выполняется",done:"Готово",completed:"Завершён",passed:"Пройден",review:"Есть замечания",failed:"Ошибка",skipped:"Пропущен",error:"Ошибка",pending:"Ожидает",partial:"Частичный результат"};
  const stageMap=new Map((run.stages||[]).map(s=>[s.id,s]));
  const findings=run.findings||[], summary=run.summary, active=["running","queued","pending"].includes(run.status);
  const source=run.source, revision=source?.revision || "";
  const commitLink=/^[\w.-]+\/[\w.-]+$/.test(source?.repository || "") && /^[a-f0-9]{40}$/.test(revision);
  const revisionLabel=revision?`<code title="${e(revision)}">${e(revision.slice(0,12))}</code>`:"";
  const revisionMarkup=commitLink?`<a href="https://github.com/${e(source.repository)}/commit/${e(revision)}" target="_blank" rel="noopener noreferrer">${revisionLabel}</a>`:revisionLabel;
  const place=f=>`${f.path}${f.line?` · ${f.line}${f.endLine&&f.endLine!==f.line?"–"+f.endLine:""}`:""}`;
  const count=x=>x?.count===undefined?"—":`${x.count}${Object.keys(x.categories||{}).length?" · "+Object.entries(x.categories).map(([a,b])=>`${a} ${b}`).join(", "):""}`;
  function packet(stage, side){
    const data=stage[side], sample=data?.sample||[];
    const files=data?.files ?? (stage.type==="source"&&side==="output"&&stage.status==="done" || ["sca","secrets","sast"].includes(stage.type)&&side==="input"&&stage.status!=="skipped" ? run.source?.files:undefined);
    const filesLabel=files===undefined?"":`Файлов: ${e(files)}`;
    if(!sample.length)return filesLabel || e(count(data));
    const remaining=Math.max(0,data.count-sample.length);
    return `<details data-packet="${e(stage.id)}-${side}"><summary>${filesLabel?filesLabel+" · ":""}${e(count(data))}</summary><ul>${sample.map(ref=>{
      const where=ref.path?place(ref):ref.line?"Строка "+ref.line:"";
      return `<li><strong>${e(ref.category)}</strong> <code>${e(where)} ${e(ref.advisoryId||"")}</code></li>`;}).join("")}</ul>${remaining?`<small>Ещё ${e(remaining)}</small>`:""}</details>`;
  }
  const origin=({model:"Рекомендации модели",catalog:"Рекомендации каталога",mixed:"Модель и каталог рекомендаций"});
  const locations=refs=>`<ul>${(refs||[]).map(ref=>`<li><code>${e(place(ref))}${ref.advisoryId?" · "+e(ref.advisoryId):""}</code></li>`).join("")}</ul>`;
  function verification(group){
    const v=group.verification;
    if(v?.status==="verified"&&v.scope==="structuredEvidence"&&v.fact)return `<section class="studio-fact" aria-label="Подтверждённый факт">
      <p class="studio-verified"><span aria-hidden="true">✓</span> Проверено системой</p>
      <p>Анализатор зарегистрировал находки типа <strong>${e(v.fact.riskCode)}</strong>. Количество · ${e(v.fact.count)}.</p>${locations(v.fact.evidence)}</section>`;
    if(v?.status==="mismatch")return `<p class="studio-mismatch">Расхождение с фактами · ${e((v.reasons||[]).join(" "))}</p>`;
    return locations(group.evidence);
  }
  function decision(f){
    if(f.decision?.status==="false_positive")return '<small class="chip">Отмечено как ложное срабатывание</small>';
    const a=f.telegramAction;if(!a)return "";
    const status={queued:"Исправление в очереди",working:"Подготовка PR",fixed:"PR с исправлением",failed:"Ошибка создания PR",dismissed:"Пропущено"}[a.status];
    if(!status)return "";
    return a.status==="fixed"&&/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/pull\/\d+$/.test(a.result)?
      `<a href="${e(a.result)}" target="_blank" rel="noopener noreferrer">${status}</a>`:`<small class="chip">${status}</small>`;
  }
  return `<div class="studio-report-heading"><h3>Проверка ${e(String(run.id).slice(0,8))}</h3><span class="chip">${e(state[run.status]||run.status)}</span>
    <button type="button" class="link-button" data-copy-report>Скопировать ссылку на отчёт</button></div>
    <label data-manual-copy class="field" hidden>Ссылка для участников проекта<input type="url" readonly></label>
    ${source?`<p class="studio-source-meta">${e(source.repository || "Загруженный проект")} ${revisionMarkup?"· "+revisionMarkup:""}
      · ${source.inventory ? `файлов в снимке ${e(source.inventory.totalFiles)} · ` : ""}текстовых файлов передано ${e(source.files)}</p>`:""}
    ${Array.isArray(run.coverage) ? `<p>Файлов с проверенным содержимым · ${new Set(run.coverage.filter(row => row.status === "done" && row.engine !== "repository").map(row => row.file)).size}</p>` : ""}
    ${run.skipReason ? `<p>${e(run.skipReason)}</p>` : ""}
    ${run.source?.scopeNote?`<p class="studio-source-meta">${e(run.source.scopeNote)}</p>`:""}
    ${run.error?`<p role="alert">${e(run.error)}</p>`:""}
    ${stageMap.size?`<div class="studio-stage-list"><table><caption>Передача данных между блоками</caption><thead><tr><th>Блок</th><th>Состояние</th><th>Вход</th><th>Выход</th></tr></thead><tbody>${Array.from(stageMap.values(),s=>`<tr><th scope="row">${e(labels[s.type]||s.type||s.id)} <small>${e(s.id)}</small></th><td>${e(state[s.status]||s.status)}</td><td>${packet(s,"input")}</td><td>${packet(s,"output")}${s.output?.port==="true"?" · ветка «Да»":s.output?.port==="false"?" · ветка «Нет»":""}</td></tr>`).join("")}</tbody></table></div>`:""}
    ${active?"":`<div class="studio-report-heading"><h3>Находки (${findings.length})</h3><button type="button" class="button" data-export="json">Скачать JSON</button><button type="button" class="button" data-export="txt">Скачать текст</button></div>
      ${findings.length?`<ul class="studio-findings">${findings.map(f=>`<li><small>${e([f.category,f.severity].filter(Boolean).join(" · "))}</small><strong>${e(f.title||f.class||f.artifact)}</strong><code>${e(place(f))}</code>
      ${f.category==="SCA"?`<code>${e([f.group,f.artifact,f.version].join(":"))} · ${e(f.advisoryId)}</code>`:""}<p>${e(f.description||"")}</p><p>${e(f.remediation||f.fix||"")}</p>${decision(f)}</li>`).join("")}</ul>`:run.status==="failed"?"":"<p>Находок нет.</p>"}`}
    ${run.dependencyMetrics?renderDependencies(run.dependencyMetrics,e):""}
    ${summary?.summary?`<section class="studio-summary"><h3>${e(origin[summary.source]||"Рекомендации")}</h3>${summary.model?`<small>${e(summary.model)}</small>`:""}<p>${e(summary.summary)}</p>
      ${summary.verification?.complete===false?'<p class="studio-mismatch">Список групп расходится с результатом анализаторов.</p>':""}
      ${(summary.groups||[]).map(g=>`<details><summary>${e([g.category,g.class===g.category?"":g.class,g.source?origin[g.source]:""].filter(Boolean).join(" · "))}</summary>${verification(g)}
        <dl class="studio-advice"><dt>${g.source==="model"?"Пояснение модели":"Пояснение каталога"}</dt><dd>${e(g.summary)}</dd><dt>${g.source==="model"?"Предложение модели":"Рекомендация каталога"}</dt><dd>${e(g.action)}</dd></dl></details>`).join("")}</section>`:""}
    ${run.delivery?`<p><strong>Оповещение</strong> · ${e(({sent:run.delivery.channel==="telegram"?"Принято Telegram":"Принято SMTP",failed:"Ошибка доставки",unknown:"Статус неизвестен",temporary:"Временный сбой",skipped:"Пропущено"})[run.delivery.status]||run.delivery.status)}. ${e(run.delivery.message||"")}</p>`:""}`;
}

export function bindReportActions(host, project, currentRun, announce) {
  host.addEventListener("click", async event => {
    const button=event.target.closest("button"), run=currentRun();
    if(!button||!run)return;
    if(button.hasAttribute("data-export")){
      exportReport(run,button.dataset.export);
      return;
    }
    if(!button.hasAttribute("data-copy-report"))return;
    const url=new URL("/",location.origin);
    url.searchParams.set("project",project);
    url.hash="report/"+encodeURIComponent(run.id);
    const field=host.querySelector("[data-manual-copy]");
    try{
      await navigator.clipboard.writeText(url.href);
      field.hidden=true;
      announce("Ссылка на отчёт скопирована. Открыть её могут участники проекта.");
    }catch{
      const input=field.querySelector("input");
      field.hidden=false;input.value=url.href;input.focus();input.select();
      announce("Браузер ограничил доступ к буферу. Скопируйте выделенный адрес.");
    }
  });
}

export function exportReport(run, format) {
  const findings=run.findings||[];
  const parts=findings.map(f=>[`${f.category} · ${f.title||f.class||f.artifact} · ${f.severity||""}`, `${f.path}${f.line?":"+f.line+(f.endLine&&f.endLine!==f.line?"–"+f.endLine:""):""}`,
    f.category==="SCA"?`${f.group}:${f.artifact}:${f.version} · ${f.advisoryId}`:"",f.description,f.remediation||f.fix].filter(Boolean).join("\n"));
  const data=format==="json"?JSON.stringify({findings},null,2):[`Проверка ${run.id}`,`Находки (${findings.length})`,...(parts.length?parts:["Находок нет."]),run.summary?.summary].filter(Boolean).join("\n\n");
  const url=URL.createObjectURL(new Blob([data+"\n"],{type:format==="json"?"application/json;charset=utf-8":"text/plain;charset=utf-8"}));
  const a=document.createElement("a");a.href=url;a.download=`Штопка-${run.id}.${format}`;a.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
}
