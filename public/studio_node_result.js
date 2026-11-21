import {portNames,portTypes,typeNames} from "/studio_ports.js";

const stageNames = {done:"Готово", running:"Выполняется", error:"Ошибка", skipped:"Ветка пропущена"};
const origins = {model:"Модель", mixed:"Модель и каталог", catalog:"Каталог рекомендаций"};
const verificationNames = {verified:"Подтверждено", mismatch:"Обнаружено расхождение", catalog:"Из каталога"};

export function nodeResult(run, node, escape) {
  if (!run) return "";
  const stage = run.stages?.find(s => s.id === node.id);
  const header = '<section class="node-result" data-node-result><h3>Данные запуска</h3>';
  if (!stage) return header + `<p>${["running","queued","pending"].includes(run.status)
    ? "Шаг ожидает выполнения." : "Для этого шага в запуске нет данных."}</p></section>`;
  if (stage.status === "skipped") return header + "<p>Условие направило данные по другой ветке.</p></section>";
  const e = escape;
  const trace = run.trace;
  const input = trace?.inputs?.[node.id], output = trace?.outputs?.[node.id];
  const findings = refs => refs?.map(i => trace.findings?.[i]).filter(Boolean);
  const files = trace?.snapshot?.files || [];
  const title = text => `<h4>${e(text)}</h4>`;
  const value = text => `<p>${e(text)}</p>`;
  const json = (label, obj) => `<details class="node-data-json"><summary>${e(label)}</summary><pre tabindex="0">${e(JSON.stringify(obj, null, 2))}</pre></details>`;
  function portValues(ports) {
    return Object.entries(ports || {}).map(([port,data]) => {
      const label = (portNames[port] || port) + " · " + (typeNames[portTypes[port]] || "");
      if (Array.isArray(data)) return json(label + " (" + data.length + ")",data);
      return value(label + " · " + (typeof data === "boolean" ? (data ? "Да" : "Нет") : String(data)));
    }).join("");
  }
  function matches(rows, summary) {
    const count = rows?.length ?? summary?.count;
    if (count == null) return "";
    const sample = rows || summary?.sample || [];
    return value("Находки · " + count) + (sample.length ? `<ul>${sample.slice(0, 5).map(f =>
      `<li><strong>${e(f.class || f.category)}</strong> <code>${e([f.path,f.line,f.column].filter(v => v != null).join(":"))}</code></li>`).join("")}</ul>` : "");
  }
  function advice(result) {
    if (!result) return "";
    return value([origins[result.source], result.model].filter(Boolean).join(" · ")) + value(result.summary || "") +
      (result.reason ? value(result.reason) : "") + (result.groups || []).map(g =>
        `<details class="node-advice"><summary>${e(g.class || g.category)} · ${e(g.evidence?.length ?? 0)}</summary>
        <p><strong>Риск</strong> ${e(g.summary)}</p><p><strong>Исправление</strong> ${e(g.action)}</p>
        ${g.verification ? value(verificationNames[g.verification.status] || g.verification.status) : ""}</details>`).join("");
  }
  const inRows = findings(input?.refs), outRows = findings(output?.refs);
  let before = "", after = "";
  const stringNode = node.type === "regex" || node.type === "custom";
  const inData = input ? (node.type === "regex" ? {pattern:node.params.pattern} : node.type === "custom" ? {steps:node.params.steps} : {findings:inRows}) : stage.input && {...stage.input};
  const outData = output ? (stringNode ? {} : {port:output.port,findings:outRows}) : stage.output && {...stage.output};
  if (input?.trigger) {
    const descriptions = {manual:"Команда ручного запуска",schedule:"Наступило время расписания",
      github_pr:"Получено событие pull request",github_push:"Получено обновление ветки",webhook:"Получена команда CI/CD"};
    before = value(descriptions[input.trigger] || input.trigger);
    inData.trigger = input.trigger;
    if (input.event) {
      inData.event = input.event;
      before += value("Коммит · " + input.event.revision.slice(0,12));
      if (input.event.prNumber) before += value("Pull request №" + input.event.prNumber);
      if (input.event.ref) before += value("Ветка · " + input.event.ref.replace(/^refs\/heads\//,""));
    }
  } else if (input?.source) {
    before = value(input.source.kind === "repository" ? "Запрошен снимок репозитория" : "Переданы файлы проекта");
    inData.source = input.source;
  } else if (!stringNode) {
    before = matches(inRows, stage.input);
  }
  if (input?.fileRefs) {
    inData.files = input.fileRefs.map(i => files[i]).filter(Boolean);
    before += value("Файлы на входе · " + inData.files.length);
  } else if (stage.input?.files != null) before += value("Файлы на входе · " + stage.input.files);
  if (input?.sensitivePathRefs?.length) {
    const paths = run.source?.inventory?.sensitivePaths || [];
    inData.sensitivePaths = input.sensitivePathRefs.map(i => paths[i]).filter(Boolean);
    before += value("Имена файлов для проверки на секреты · " + inData.sensitivePaths.length);
  }
  if (input?.modelInputs) {
    inData.modelInputs = input.modelInputs;
    if (input.model) inData.model = input.model;
    before += value(input.modelInputs.length
      ? "Группы для модели " + input.model + " · " + input.modelInputs.length
      : "Обращения к модели · 0");
  }
  if (input?.recommendationNodes?.length) {
    inData.recommendations = input.recommendationNodes.map(id => run.explanations?.[id]).filter(Boolean);
    before += value("Получены рекомендации · " + inData.recommendations.length);
  }
  const explanation = run.explanations?.[node.id];
  const receipt = run.deliveries?.[node.id];
  if (node.type === "ai_review" && run.aiReviews?.[node.id]) {
    const review=run.aiReviews[node.id];
    before=value("Проверено файлов · "+review.filesExamined)+value("Статических признаков для модели · "+review.candidates);
    after=value("Модель · "+(review.model || "не вызвана"))+value("Отклонено предложений · "+review.rejected)+json("Предложения для ручной проверки",review.suggestions);
    if(outData)outData.review=review;
  } else if (receipt) {
    after = value(receipt.channel === "telegram" ? "Telegram" : "SMTP") + value(receipt.message);
    if (outData) outData.delivery = receipt;
  } else if (stage.status !== "done") {
    after = value(stage.status === "error" ? "Шаг завершился с ошибкой до передачи результата." : "Ожидаем результат.");
  } else if (["manual", "schedule", "github_pr", "github_push", "webhook"].includes(node.type)) {
    after = value("Проверка запущена.");
  } else if (node.type === "source") {
    const source = run.source || {};
    after = value([source.repository || "Загруженный проект", source.revision?.slice(0,12)].filter(Boolean).join(" · ")) +
      value("Текстовых файлов · " + (source.files ?? files.length));
    if (output && trace.snapshot) outData.snapshot = trace.snapshot;
  } else if (node.type === "condition") {
    after = value((output?.port || stage.output?.port) === "true" ? "Выбрана ветка «Да»." : "Выбрана ветка «Нет».") + matches(outRows, stage.output);
  } else if (explanation) {
    after = advice(explanation);
    if (outData) outData.recommendation = explanation;
  } else if (!stringNode) after = matches(outRows, stage.output);
  if (output?.coverage) {
    outData.coverage = output.coverage;
    after += value("Успешно проверено файлов · " + output.coverage.checked);
    const errors = output.coverage.errors || [];
    if (errors.length) after += value("Не удалось проверить файлов · " + errors.length) +
      `<ul>${errors.slice(0, 5).map(f => `<li><code>${e([f.file, f.line].filter(Boolean).join(":"))}</code></li>`).join("")}</ul>`;
  }
  if (input?.ports) inData.ports = input.ports;
  if (output?.ports) outData.ports = output.ports;
  return header + value(stageNames[stage.status] || stage.status) + title("Вход") + before + portValues(input?.ports) +
    (inData ? json(input ? "Показать входные данные" : "Сохранённая сводка входа", inData) : "") +
    title("Выход") + after + portValues(output?.ports) + ((output || receipt || stage.status === "done") && outData ?
      json(output ? "Показать выходные данные" : "Сохранённая сводка выхода", outData) : "") + "</section>";
}
