import {renderDependencies} from "/studio_dependencies.js";
import {discussion} from "/studio_discussion.js";
import {modelPortLabel} from "/studio_ports.js";

export function routeInventory(rows, e) {
  const annotation = row => row.security === "method-annotation" ? "@" + row.securityAnnotation : "Не определён";
  return rows.length ? `<div class="studio-stage-list"><table><thead><tr><th>Маршрут</th><th>Обработчик</th><th>Доступ</th></tr></thead><tbody>
      ${rows.map(row => `<tr><td><code>${e(row.method)} ${e(row.route)}</code></td>
        <td>${e(row.handler)} <code>${e(row.path)}:${e(row.line)}</code></td><td>${e(annotation(row))}</td></tr>`).join("")}
    </tbody></table></div>` : "<p>Маршрутов с поддерживаемыми аннотациями не найдено.</p>";
}

export function stageStatus(run, stage) {
  const errors = run?.trace?.outputs?.[stage.id]?.coverage?.errors;
  const rejected = run?.aiReviews?.[stage.id]?.rejected;
  return stage.status === "done" && (errors?.length || rejected > 0) ? "partial" : stage.status;
}

function emptyFindingsMessage(run) {
  if (run.status === "partial") {
    return run.coverage?.some(row => row.status === "done")
      ? "В проверенной части находок нет."
      : "Часть данных не удалось проверить. Подробности в результатах шагов.";
  }
  if (run.status === "skipped") return run.skipReason || "Проверка пропущена.";
  if (run.status === "failed") return run.error || "Проверка завершилась с ошибкой.";
  return "Находок нет.";
}

export function reportMarkup(run,e,labels) {
  const state={queued:"В очереди",running:"Выполняется",done:"Готово",completed:"Завершён",passed:"Пройден",review:"Есть замечания",failed:"Ошибка",skipped:"Пропущен",error:"Ошибка",pending:"Ожидает",partial:"Частичный результат"};
  const stageMap=new Map((run.stages||[]).map(s=>[s.id,s]));
  const findings=run.findings||[], summary=run.summary, active=["running","queued","pending"].includes(run.status);
  const coverageErrors=(run.coverage||[]).filter(row=>row.status==="error");
  const source=run.source, revision=source?.revision || "";
  const commitLink=/^[\w.-]+\/[\w.-]+$/.test(source?.repository || "") && /^[a-f0-9]{40}$/.test(revision);
  const revisionLabel=revision?`<code title="${e(revision)}">${e(revision.slice(0,12))}</code>`:"";
  const revisionMarkup=commitLink?`<a href="https://github.com/${e(source.repository)}/commit/${e(revision)}" target="_blank" rel="noopener noreferrer">${revisionLabel}</a>`:revisionLabel;
  const place=f=>`${f.path}${f.line?` · ${f.line}${f.column?":"+f.column:""}${f.endLine&&f.endLine!==f.line?"–"+f.endLine:""}`:""}`;
  const count=x=>x?.count===undefined?"—":`${x.count}${Object.keys(x.categories||{}).length?" · "+Object.entries(x.categories).map(([a,b])=>`${a} ${b}`).join(", "):""}`;
  function packet(stage, side){
    const data=stage[side], sample=data?.sample||[];
    const model=run.trace?.[side+"s"]?.[stage.id]?.ports?.model;
    const modelLabel=model?`<small>${e(modelPortLabel(model))}</small>`:"";
    const files=data?.files ?? (stage.type==="source"&&side==="output"&&stage.status==="done" || ["sca","secrets","sast"].includes(stage.type)&&side==="input"&&stage.status!=="skipped" ? run.source?.files:undefined);
    const filesLabel=files===undefined?"":`Файлов: ${e(files)}`;
    if(!sample.length)return model && stage.type==="model_load" ? modelLabel : (filesLabel || e(count(data))) + modelLabel;
    const remaining=Math.max(0,data.count-sample.length);
    return `<details data-packet="${e(stage.id)}-${side}"><summary>${filesLabel?filesLabel+" · ":""}${e(count(data))}</summary><ul>${sample.map(ref=>{
      const where=ref.path?place(ref):ref.line?"Строка "+ref.line:"";
      return `<li><strong>${e(ref.category)}</strong> <code>${e(where)} ${e(ref.advisoryId||"")}</code></li>`;}).join("")}</ul>${remaining?`<small>Ещё ${e(remaining)}</small>`:""}</details>${modelLabel}`;
  }
  function stageState(stage) {
    const status = stageStatus(run, stage);
    const label = status === "partial" ? "Проверено частично" : state[status] || status;
    return e(label) + (stage.message ? `<small>${e(stage.message)}</small>` : "");
  }
  const origin=({model:"Рекомендации модели",catalog:"Рекомендации каталога",mixed:"Модель и каталог рекомендаций"});
  const locations=refs=>`<ul>${(refs||[]).map(ref=>`<li><code>${e(place(ref))}${ref.advisoryId?" · "+e(ref.advisoryId):""}</code></li>`).join("")}</ul>`;
  function verification(group){
    const v=group.verification;
    if(v?.status==="verified"&&v.scope==="structuredEvidence"&&v.fact)return `<section class="studio-fact" aria-label="Сверенные данные находок">
      <p class="studio-verified"><span aria-hidden="true">✓</span> Данные находок сверены</p>
      <p>Анализатор зарегистрировал находки типа <strong>${e(v.fact.riskCode)}</strong>. Количество · ${e(v.fact.count)}.</p>${locations(v.fact.evidence)}</section>`;
    if(v?.status==="mismatch")return `<p class="studio-mismatch">Данные модели расходятся с находками. Показана рекомендация каталога. ${e((v.reasons||[]).join(" "))}</p>`;
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
    ${coverageErrors.length ? `<details><summary>Что не удалось проверить (${coverageErrors.length})</summary><ul>${coverageErrors.map(row=>`<li><code>${e(row.file)}${row.line?":"+e(row.line):""}</code> · ${e(row.message||"Ошибка проверки")}</li>`).join("")}</ul></details>` : ""}
    ${run.skipReason ? `<p>${e(run.skipReason)}</p>` : ""}
    ${run.source?.scopeNote?`<p class="studio-source-meta">${e(run.source.scopeNote)}</p>`:""}
    ${run.error?`<p role="alert">${e(run.error)}</p>`:""}
    ${stageMap.size?`<div class="studio-stage-list"><table><caption>Передача данных между блоками</caption><thead><tr><th>Блок</th><th>Состояние</th><th>Вход</th><th>Выход</th></tr></thead><tbody>${Array.from(stageMap.values(),s=>`<tr><th scope="row">${e(labels[s.type]||s.type||s.id)} <small>${e(s.id)}</small></th><td>${stageState(s)}</td><td>${packet(s,"input")}</td><td>${packet(s,"output")}${s.output?.port==="true"?" · ветка «Да»":s.output?.port==="false"?" · ветка «Нет»":""}</td></tr>`).join("")}</tbody></table></div>`:""}
    ${active?"":`<div class="studio-report-heading"><h3>Находки (${findings.length})</h3><button type="button" class="button" data-export="json">Скачать JSON</button><button type="button" class="button" data-export="txt">Скачать текст</button><button type="button" class="button" data-export="sarif">Скачать SARIF</button></div>
      ${findings.length?`<ul class="studio-findings">${findings.map((f,i)=>`<li><small>${e([f.checkId,f.category,f.severity].filter(Boolean).join(" · "))}</small><strong>${e(f.title||f.class||f.artifact)}</strong><code>${e(place(f))}</code><button type="button" class="link-button" data-discuss="${i}">Обсудить с ИИ</button>
      ${f.category==="SCA"?`<code>${e([f.group,f.artifact,f.version].join(":"))} · ${e(f.advisoryId)}</code>`:""}<p>${e(f.description||"")}</p><p>${e(f.remediation||f.fix||"")}</p>${decision(f)}</li>`).join("")}</ul>`:run.status==="failed"||run.skipReason?"":`<p>${e(emptyFindingsMessage(run))}</p>`}`}
    ${Object.values(run.aiReviews || {}).map(r=>`<section><h3>Экспериментальный ИИ-обзор</h3><p>${e(r.model)} · проверено файлов: ${e(r.filesExamined)} · кандидатов: ${e(r.candidates)} · отклонено ответов: ${e(r.rejected)}</p>
      <ul>${r.suggestions.map(s=>`<li><code>${e(place(s))}</code> · ${e(s.advice)}</li>`).join("")}</ul></section>`).join("")}
    ${Object.values(run.sourceRoutes || {}).map(rows=>`<details><summary>Маршруты Spring (${rows.length})</summary>${routeInventory(rows,e)}</details>`).join("")}
    ${run.dependencyMetrics?renderDependencies(run.dependencyMetrics,e):""}
    ${summary?.summary?`<section class="studio-summary"><h3>${e(origin[summary.source]||"Рекомендации")}</h3>${summary.model?`<small>Модель запроса · ${e(summary.model)}</small>`:""}<p>${e(summary.summary)}</p>
      ${summary.reason?`<p>${e(summary.reason)}</p>`:""}
      ${summary.verification?.complete===false?'<p class="studio-mismatch">Список групп расходится с результатом анализаторов.</p>':""}
      ${(summary.groups||[]).map(g=>`<details><summary>${e([g.category,g.class===g.category?"":g.class,g.source?origin[g.source]:""].filter(Boolean).join(" · "))}</summary>${verification(g)}
        ${g.source==="model"?'<p><small>Текст модели требует проверки.</small></p>':""}
        <dl class="studio-advice"><dt>${g.source==="model"?"Пояснение модели":"Пояснение каталога"}</dt><dd>${e(g.summary)}</dd><dt>${g.source==="model"?"Предложение модели":"Рекомендация каталога"}</dt><dd>${e(g.action)}</dd></dl></details>`).join("")}</section>`:""}
    ${run.delivery?`<p><strong>Оповещение</strong> · ${e(({sent:({telegram:"Принято Telegram",webhook:"Принято HTTP-вебхуком",smtp:"Принято SMTP"})[run.delivery.channel] || "Доставлено",failed:"Ошибка доставки",unknown:"Статус неизвестен",temporary:"Временный сбой",skipped:"Пропущено"})[run.delivery.status]||run.delivery.status)}. ${e(run.delivery.message||"")}</p>`:""}`;
}

export function bindReportActions(host, project, currentRun, announce, request) {
  host.addEventListener("click", async event => {
    const button=event.target.closest("button"), run=currentRun();
    if(!button||!run)return;
    if(button.hasAttribute("data-discuss")){
      discussion(host.closest(".studio") || host, project, run, Number(button.dataset.discuss), request);
      return;
    }
    if(button.dataset.export==="sarif"){
      const url = "/api/studio/run?" + new URLSearchParams({project, id:run.id, format:"sarif"});
      try {
        const response = await fetch(url, {headers: {"X-Workspace-Session":"1"}});
        if (!response.ok) throw new Error("Не удалось скачать SARIF.");
        saveBlob(await response.blob(), `report-${run.id}.sarif`);
      } catch (error) {
        announce(error.message, true);
      }
      return;
    }
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
  const document = run.sourceRoutes ? {findings, sourceRoutes:run.sourceRoutes} : {findings};
  const data=format==="json"?JSON.stringify(document,null,2):[`Проверка ${run.id}`,`Находки (${findings.length})`,...(parts.length?parts:[emptyFindingsMessage(run)]),run.summary?.summary].filter(Boolean).join("\n\n");
  saveBlob(new Blob([data+"\n"],{type:format==="json"?"application/json;charset=utf-8":"text/plain;charset=utf-8"}), `Штопка-${run.id}.${format}`);
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
