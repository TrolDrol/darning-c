import {portNames,portTypes,typeNames,modelPortLabel} from "/studio_ports.js";
import {routeInventory,stageStatus} from "/studio_report.js";

const stageNames = {done:"Готово", partial:"Проверено частично", running:"Выполняется", error:"Ошибка", skipped:"Пропущен"};
const origins = {model:"Модель", mixed:"Модель и каталог", catalog:"Каталог рекомендаций"};
const verificationNames = {
  verified:"Тип, количество и координаты находок сверены.",
  mismatch:"Данные модели расходятся с находками. Показана рекомендация каталога.",
  catalog:"Рекомендация из каталога."
};

export function nodeResult(run, node, escape) {
  if (!run) return "";
  const stage = run.stages?.find(s => s.id === node.id);
  const header = '<section class="node-result" data-node-result><h3>Данные запуска</h3>';
  if (!stage) return header + `<p>${["running","queued","pending"].includes(run.status)
    ? "Шаг ожидает выполнения." : "Для этого шага в запуске нет данных."}</p></section>`;
  const e = escape;
  if (stage.status === "skipped") {
    const inputs = stage.missingInputs?.map(key => portNames[key]).filter(Boolean) || [];
    const reason = stage.message || (inputs.length
      ? "Данные не поступили на входы: " + inputs.join(", ") + "."
      : "Данные для этого шага не поступили.");
    return header + `<p>Шаг пропущен. ${e(reason)}</p></section>`;
  }
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
      if (portTypes[port] === "model" && data && typeof data === "object") {
        return value(modelPortLabel(data));
      }
      if (Array.isArray(data)) return json(label + " (" + data.length + ")",data);
      return value(label + " · " + (typeof data === "boolean" ? (data ? "Да" : "Нет") : String(data)));
    }).join("");
  }
  function matches(rows, summary) {
    const count = rows?.length ?? summary?.count;
    if (count == null) return "";
    const sample = rows || summary?.sample || [];
    return value("Находки · " + count) + (sample.length ? `<ul>${sample.slice(0, 5).map(findingRow).join("")}</ul>` : "");
  }
  const findingRow = f => `<li><strong>${e(f.class || f.category)}</strong> <code>${e([f.path,f.line,f.column].filter(v => v != null).join(":"))}</code></li>`;
  function conditionReason() {
    const reason = trace?.conditions?.[node.id];
    if (!reason) return "";
    let detail;
    if (reason.source === "found") {
      detail = value("Логический вход · " + (reason.observed ? "Да" : "Нет"));
    } else if (reason.source === "match") {
      const field = {category:"категории", severity:"критичности", path:"пути"}[reason.field];
      const row = trace.findings?.[reason.ref];
      detail = value((reason.observed ? "Совпадение по " : "Нет совпадений по ") + field + ".") +
        (row ? `<ul>${findingRow(row)}</ul>` : "");
    } else {
      const label = reason.source === "count" ? "Количество на входе" : "Количество находок в потоке";
      detail = value(label + " · " + reason.observed) +
        value("Условие · " + (reason.operator === "eq" ? "= " : "≥ ") + reason.expected);
    }
    return title("Основание выбора ветки") + detail;
  }
  function advice(result) {
    if (!result) return "";
    return value([origins[result.source], result.model].filter(Boolean).join(" · ")) + value(result.summary || "") +
      (result.reason ? value(result.reason) : "") + (result.groups || []).map(g =>
        `<details class="node-advice"><summary>${e(g.class || g.category)} · ${e(g.evidence?.length ?? 0)}</summary>
        ${g.verification ? value(verificationNames[g.verification.status] || g.verification.status) : ""}
        ${g.source === "model" ? '<p><small>Текст модели требует проверки.</small></p>' : ""}
        <p><strong>Риск</strong> ${e(g.summary)}</p><p><strong>Исправление</strong> ${e(g.action)}</p></details>`).join("");
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
    if (Number.isFinite(input.scheduledAt)) {
      const timeZone = node.params.timezone || "UTC";
      const slot = new Intl.DateTimeFormat("ru-RU", {dateStyle:"short", timeStyle:"short", timeZone});
      before += value("По расписанию · " + slot.format(input.scheduledAt * 1000) + " (" + timeZone + ")");
      inData.scheduledAt = input.scheduledAt;
    }
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
  if (input?.comparison) {
    const comparison = input.comparison;
    inData.comparison = comparison;
    if (comparison.mergeBaseSha) before += value("Общий предок · " + comparison.mergeBaseSha.slice(0, 12));
    if (comparison.headSha) before += value("Проверяемый коммит · " + comparison.headSha.slice(0, 12));
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
    after = value({telegram:"Telegram",webhook:"HTTP-вебхук",smtp:"SMTP"}[receipt.channel] || receipt.channel) + value(receipt.message);
    if (receipt.channel === "webhook") {
      if (receipt.httpStatus != null) after += value("Ответ · HTTP " + receipt.httpStatus);
      after += value("Попыток · " + receipt.attempts);
      if (receipt.acknowledged != null) {
        const acknowledgment = typeof receipt.acknowledged === "boolean" ? (receipt.acknowledged ? "Да" : "Нет") : receipt.acknowledged;
        after += value("Подтверждение получателя · " + acknowledgment);
      }
    }
    if (outData) outData.delivery = receipt;
  } else if (stage.status !== "done") {
    after = value(stage.status === "error" ? stage.message || "Шаг завершился с ошибкой до передачи результата." : "Ожидаем результат.");
  } else if (["manual", "schedule", "github_pr", "github_push", "webhook"].includes(node.type)) {
    after = value("Проверка запущена.");
  } else if (node.type === "model_load") {
    before = value("Получен сигнал запуска.");
    after = value("Подключение передано шагам ИИ.");
  } else if (node.type === "source") {
    const source = run.source || {};
    after = value([source.repository || "Загруженный проект", source.revision?.slice(0,12)].filter(Boolean).join(" · ")) +
      value("Текстовых файлов · " + (source.files ?? files.length));
    if (output && trace.snapshot) outData.snapshot = trace.snapshot;
  } else if (node.type === "spring_routes") {
    const routes = run.sourceRoutes?.[node.id] || [];
    after = routeInventory(routes, e);
    if (outData) outData.routes = routes;
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
      `<ul>${errors.slice(0, 5).map(f => `<li><code>${e([f.file, f.line].filter(Boolean).join(":"))}</code> ${e(f.message || "")}</li>`).join("")}</ul>`;
  }
  if (input?.ports) inData.ports = input.ports;
  if (output?.ports) outData.ports = output.ports;
  const status = stageStatus(run, stage);
  return header + value(stageNames[status] || status) + title("Вход") + before + portValues(input?.ports) +
    (inData ? json(input ? "Показать входные данные" : "Сохранённая сводка входа", inData) : "") +
    (node.type === "condition" ? conditionReason() : "") +
    title("Выход") + after + portValues(output?.ports) + ((output || receipt || stage.status === "done") && outData ?
      json(output ? "Показать выходные данные" : "Сохранённая сводка выхода", outData) : "") + "</section>";
}
