import {nodeResult} from "/studio_node_result.js";
import {inputPorts, outputPorts, portNames as portName, portTypes, typeNames} from "/studio_ports.js";

export const labels = {
  "manual": "Ручной запуск",
  "schedule": "Расписание",
  "source": "Репозиторий",
  "secrets": "Поиск секретов",
  "sca": "Зависимости",
  "sast": "Анализ кода",
  "regex": "Поиск по Regex",
  "condition": "Условие",
  "explain": "Объяснение ИИ",
  "verify": "Контроль фактов",
  "notify": "Оповещение"
};

export function localTimezone(){return Intl.DateTimeFormat().resolvedOptions().timeZone || "Europe/Moscow";}

const TILE = 72;
const HALF = TILE / 2;
const trigger = type => type === "manual" || type === "schedule";
const expanded = node => ["source","condition","regex"].includes(node.type);
const width = node => expanded(node) ? 178 : TILE;
const height = node => expanded(node) ? 52 + 26 * Math.max(inputPorts(node.type).length,outputPorts(node.type).length) : TILE;
const portY = (node,port,input = false) => expanded(node)
  ? 54 + 26 * (input ? inputPorts : outputPorts)(node.type).indexOf(port) : HALF;
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
const subtitles = {manual:"По кнопке", source:"Снимок файлов", secrets:"Текстовые файлы", sca:"Gradle / Maven",
  sast:"По типу файла", regex:"Регулярное выражение", condition:"Если / иначе", explain:"Рекомендации", verify:"Доказательства", notify:"Почта"};
const hints = {manual:"Запускает проверку по кнопке.", schedule:"Запускает сохранённый сценарий ежедневно по местному времени выбранного часового пояса.",
  source:"Принимает снимок репозитория, папку или архив проекта.", secrets:"Ищет признаки встроенных учётных данных в тексте.",
  sca:"Сверяет прямые зависимости Gradle и Maven со справочником.", sast:"Применяет правила к Python, JSON, Kotlin и конфигурации Spring.",
  regex:"Ищет совпадения в каждой строке. Соедините выход с подходящим входом другого блока.",
  condition:"Выбирает ветку для всего набора найденных замечаний.", explain:"Группирует находки и готовит рекомендации по исправлению.",
  verify:"Сверяет заявленный моделью тип риска, число находок и координаты со снимком запуска.", notify:"Отправляет сводку через выбранный канал проекта."};
const symbols = {
  manual:'<path d="M8 4.5 20 12 8 19.5z"/>', schedule:'<circle cx="12" cy="12" r="8.3"/><path d="M12 7v5l3.4 1.8"/>',
  source:'<path d="M3.5 6.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/><path d="m10 10.5-2.5 2.3 2.5 2.3m4-4.6 2.5 2.3-2.5 2.3"/>',
  secrets:'<circle cx="9" cy="10" r="4.8"/><path d="m12.5 13.5 6.2 6.2m-2.5-2.5 2.1-2.1m-4.3-.1 2.1-2.1"/>',
  sca:'<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9zm-8 4.5 8 4.6 8-4.6M12 12v9m-4-16 8 4.6"/>',
  sast:'<path d="m7.8 7.2-4.9 4.9 4.9 4.8m8.4-9.7 4.9 4.9-4.9 4.8m-2.1-12.7-4 15.3"/>',
  regex:'<circle cx="5" cy="18" r="1.4"/><path d="M15 4v12m-5-9 10 6M10 13l10-6"/>',
  condition:'<path d="M5 12h5m0 0c4 0 3-6 7-6h2m-9 6c4 0 3 6 7 6h2m-2.4-14.5L20 6l-3.4 2.5m0 7L20 18l-3.4 2.5"/>',
  explain:'<path d="M4 12c5 0 7-2 8-8 1 6 3 8 8 8-5 1-7 3-8 8-1-5-3-7-8-8zm13-6 1-3 1 3 3 1-3 1-1 3-1-3-3-1z"/>',
  verify:'<path d="m12 3 7.5 3v5.7c0 4.2-3.3 7.5-7.5 9.3-4.2-1.8-7.5-5.1-7.5-9.3V6z"/><path d="m8.3 12 2.5 2.5 4.9-5"/>',
  notify:'<rect x="3" y="5.6" width="18" height="12.8" rx="2"/><path d="m4 7 8 5.6L20 7"/>'
};
export const nodeIcon = type => `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">${symbols[type] || ""}</svg>`;
const curve = (x, y, endX, endY) => {
  const bend = clamp(Math.abs(endX - x) * .48, 34, 140);
  return `M ${x} ${y} C ${x + bend} ${y}, ${endX - bend} ${endY}, ${endX} ${endY}`;
};

export function createCanvas({section, getGraph, getReport = () => null, repositories = [], legacyBoundId,
    canWrite, escape:e, onChange, announce, onAddRequest, getAddOrigin = () => null, onInspect = () => {}}) {
  const scroller = section.querySelector(".studio-scroller");
  const plane = section.querySelector(".studio-plane");
  const panel = section.querySelector(".studio-inspector");
  scroller.classList.add("automation-canvas");
  scroller.title = "Перетащите фон, чтобы переместить схему. Ctrl + колесо меняет масштаб. Клавиша 1 вписывает граф.";
  let selected, selectedEdge, graphRef, gesture, wire, suppressClick = false, displayedResult = "";
  let scale = 1, left = 0, top = 0, autoFit = true, fullOverview = false;
  const graph = getGraph;
  const nodeById = id => graph().nodes.find(n => n.id === id);
  const degrees = id => graph().edges.filter(edge => edge.from === id || edge.to === id);
  const title = id => labels[nodeById(id)?.type] || id;
  const opts = (items, chosen) => Object.entries(items).map(([v,label]) => `<option value="${e(v)}" ${String(v) === String(chosen) ? "selected" : ""}>${e(label)}</option>`).join("");
  const focusNode = id => plane.querySelector(`[data-studio-node="${CSS.escape(id)}"]`)?.focus({preventScroll:true});
  function applyView() {
    plane.style.transform = `translate(${left}px,${top}px) scale(${scale})`;
    scroller.classList.toggle("canvas-overview-scale", scale < .68);
    scroller.style.setProperty("--caption-zoom", String(clamp(.86 / scale, 1, 5)));
    const grid = 24 * Math.max(scale, .5);
    scroller.style.backgroundSize = `${grid}px ${grid}px`;
    scroller.style.backgroundPosition = `${left}px ${top}px`;
    section.querySelector("[data-studio-fit]").textContent = Math.round(scale * 100) + " %";
  }
  function fit(explicit = true) {
    autoFit = true;
    if (explicit) fullOverview = true;
    const nodes = graph().nodes, w = scroller.clientWidth, h = scroller.clientHeight;
    if (!w || !h) return;
    const xs = nodes.map(n => n.x || 0), ys = nodes.map(n => n.y || 0);
    const x = nodes.length ? Math.min(...xs) - 52 : 0, y = nodes.length ? Math.min(...ys) - 15 : 0;
    const endX = nodes.length ? Math.max(...nodes.map(n => n.x + width(n))) + 52 : TILE;
    const endY = nodes.length ? Math.max(...nodes.map(n => n.y + height(n))) + 57 : TILE;
    const padding = w < 600 ? 14 : 32;
    // Leave space for the floating toolbar at the bottom of the canvas.
    const hFree = Math.max(80, h - 66);
    scale = Math.max(.001, Math.min(1.22, (w - 2 * padding) / (endX - x), (hFree - 2 * padding) / (endY - y)));
    left = (w - (endX - x) * scale) / 2 - x * scale;
    top = (hFree - (endY - y) * scale) / 2 - y * scale + 8;
    if (!fullOverview && w < 600 && scale < .82 && nodes.length) {
      const first = nodes.find(n => trigger(n.type)) || nodes[0];
      scale = .9;
      left = Math.min(75, w * .22) - (first.x + HALF) * scale;
      top = hFree / 2 - (first.y + HALF) * scale;
    }
    applyView();
  }
  function world(clientX, clientY) {
    const rect = scroller.getBoundingClientRect();
    return {x:(clientX - rect.left - left) / scale, y:(clientY - rect.top - top) / scale};
  }
  function zoom(factor, x = scroller.clientWidth / 2, y = scroller.clientHeight / 2) {
    const next = clamp(scale * factor, Math.min(.12, scale), 2.5);
    left = x - (x - left) * next / scale; top = y - (y - top) * next / scale;
    scale = next; autoFit = false; applyView();
  }
  function ensureVisible(node) {
    const w = scroller.clientWidth, h = scroller.clientHeight;
    const x = left + (node.x + width(node)/2) * scale, y = top + (node.y + height(node)/2) * scale;
    if (x >= 60 && x <= w - 60 && y >= 54 && y <= h - 100) return;
    left += w / 2 - x; top += (h - 56) / 2 - y; autoFit = false; applyView();
  }
  function inspectNode(node) {
    onInspect();
    const drawer = section.querySelector("[data-node-inspector]:not([hidden])");
    if (!drawer) return;
    const area = scroller.getBoundingClientRect(), cover = drawer.getBoundingClientRect();
    const right = left + (node.x + width(node) + 45) * scale, bottom = top + (node.y + height(node) + 44) * scale;
    const dx = cover.left - area.left - right - 14, dy = cover.top - area.top - bottom - 14;
    if (cover.height < area.height * .7 && dy < 0) top += dy;
    else if (cover.height >= area.height * .7 && cover.left - area.left > 135 && dx < 0) left += dx;
    else return;
    autoFit = false; applyView();
  }
  function edgeTitle(edge) {
    return `${title(edge.from)} · ${portName[edge.port]} → ${title(edge.to)} · ${portName[edge.input || "in"]}`;
  }
  function sent(output, port) {
    return portTypes[port] === "flow" ? output?.port === port : Object.hasOwn(output?.ports || {},port);
  }
  function drawWires() {
    const run = getReport(), markers = [["normal","#9daaa5"], ["used","#7be1a7"]];
    const markup = markers.map(([name,color]) => `<marker id="studio-arrow-${name}" markerWidth="5" markerHeight="5" refX="4" refY="2.5" orient="auto"><path d="M0,0 L5,2.5 L0,5" fill="${color}"/></marker>`);
    const paths = graph().edges.map((edge, i) => {
      const a = nodeById(edge.from), b = nodeById(edge.to);
      if (!a || !b) return "";
      const d = curve(a.x + width(a) + 5, a.y + portY(a, edge.port), b.x - 9, b.y + portY(b, edge.input || "in", true));
      const active = sent(run?.trace?.outputs?.[a.id],edge.port);
      const label = edgeTitle(edge);
      return `<g class="studio-edge ${active ? "taken" : ""} ${selectedEdge === i ? "selected-edge" : ""}" data-inspect-edge="${i}" tabindex="0" role="button" aria-label="${e(label)}">
        <path class="studio-hit" d="${d}"/><path class="studio-wire ${edge.port === "false" ? "otherwise" : ""}" d="${d}" marker-end="url(#studio-arrow-${active ? "used" : "normal"})"/></g>`;
    });
    const svg = plane.querySelector(".canvas-wires"), focused = document.activeElement?.dataset?.inspectEdge;
    svg.innerHTML = `<defs>${markup.join("")}</defs>${paths.join("")}<path class="canvas-preview" fill="none"/>`;
    if (focused !== undefined) svg.querySelector(`[data-inspect-edge="${CSS.escape(focused)}"]`)?.focus({preventScroll:true});
  }
  function subtitle(n) {
    if (n.type === "schedule") return (n.params.time || "00:00") + " " + (n.params.timezone || "UTC").split("/").pop();
    return n.type === "notify" && n.params.channel === "telegram" ? "Telegram" : subtitles[n.type];
  }
  function portMarkup(n, port, input = false) {
    const label = e(`${input ? "Вход" : "Выход"} «${portName[port]}» · ${typeNames[portTypes[port]]} · ${title(n.id)}`);
    const side = input ? "input" : "output";
    const data = input ? `data-studio-input="${e(n.id)}" data-input-key="${port}"` : `data-studio-port="${port}" data-origin="${e(n.id)}"`;
    const anchor = canWrite()
      ? `<button type="button" class="canvas-port ${side}" ${data} aria-label="${label}" title="${label}"></button>`
      : `<i class="canvas-port ${side}" title="${label}"></i>`;
    const caption = expanded(n) ? `<span class="canvas-slot-caption">${portName[port]}</span>` : "";
    const socket = `data-socket-type="${portTypes[port]}" data-socket-key="${port}"`;
    if (input) return `<div class="canvas-inlet" ${socket}>${anchor}${caption}</div>`;
    const used = graph().edges.some(edge => edge.from === n.id && edge.port === port);
    const add = canWrite() && onAddRequest && allowedTypes({from:n.id,port}).length ? `<button type="button" class="canvas-next" data-add-after="${e(n.id)}" data-after-port="${port}" aria-label="Добавить шаг после «${e(title(n.id))}», ${portName[port]}">+</button>` : "";
    return `<div class="canvas-outlet ${used ? "has-edge" : "open"}" data-port="${port}" ${socket}>${anchor}${caption}${add}</div>`;
  }
  function draw(animate = false) {
    const current = graph();
    clearWire();
    if (graphRef !== current) {selected = undefined; selectedEdge = null; autoFit = true; fullOverview = false; graphRef = current;}
    if (!nodeById(selected)) selected = current.nodes[0]?.id;
    selectedEdge = null;
    plane.innerHTML = '<svg class="canvas-wires" aria-label="Связи блоков"></svg>' + current.nodes.map(n => {
      const id = e(n.id), name = e(labels[n.type]), chosen = n.id === selected;
      const inlet = inputPorts(n.type).map(p => portMarkup(n,p,true)).join("");
      return `<div class="studio-node ${expanded(n) ? "socket-card" : ""} ${chosen ? "selected" : ""}" data-kind="${n.type}" data-studio-box="${id}">
        <button type="button" class="studio-node-body" data-studio-node="${id}" aria-pressed="${chosen}" title="${name} · ${e(subtitle(n))}" aria-label="${name}, ${id}">
          <span class="canvas-node-icon">${nodeIcon(n.type)}</span><span class="canvas-node-caption"><strong>${name}</strong><small>${e(subtitle(n))}</small></span>
        </button>${inlet}${outputPorts(n.type).map(p => portMarkup(n,p)).join("")}</div>`;
    }).join("");
    for (const box of plane.querySelectorAll("[data-studio-box]")) {
      const node = nodeById(box.dataset.studioBox);
      box.style.left = node.x + "px"; box.style.top = node.y + "px";
      box.style.width = width(node) + "px"; box.style.height = height(node) + "px";
      for (const socket of box.querySelectorAll("[data-socket-key]")) {
        socket.style.top = portY(node,socket.dataset.socketKey,socket.classList.contains("canvas-inlet")) + "px";
      }
    }
    drawWires(); if (autoFit) fit(false); else applyView(); inspect();
    if (animate && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      plane.querySelectorAll("[data-studio-box]").forEach((el,i) => el.animate([{opacity:0,transform:"translateY(7px)"},{opacity:1,transform:"translateY(0)"}],{duration:230,delay:Math.min(i,10)*32,fill:"backwards"}));
    }
  }
  function inspectPacket(index) {
    const edge = graph().edges[index], run = getReport();
    if (!edge) return;
    selectedEdge = index;
    for (const el of plane.querySelectorAll("[data-inspect-edge]")) el.classList.toggle("selected-edge", Number(el.dataset.inspectEdge) === index);
    const route = `<p>${e(edgeTitle(edge))}</p>`;
    if (!run) {
      panel.innerHTML = `<h2>Связь блоков</h2>${route}<p>После запуска здесь появятся переданные данные.</p>${canWrite() ? `<button type="button" class="button studio-delete" data-remove-edge="${index}">Удалить связь</button>` : ""}`;
      return;
    }
    const output = run.trace?.outputs?.[edge.from], delivered = sent(output,edge.port);
    const pending = ["running","queued","pending"].includes(run.status) && !output && !(run.stages || []).some(s => s.id === edge.from && ["skipped","error"].includes(s.status));
    const status = !run.trace ? "Трассировка для этого запуска не сохранена" : delivered ? "Пакет передан" : pending ? "Ожидает выполнения" : "Пакет не передавался";
    const payload = delivered && portTypes[edge.port] !== "flow" ? output.ports[edge.port] : delivered ? {port:edge.port, findings:(output.refs || []).map(i => run.trace.findings?.[i]),
      ...(output.snapshot ? {snapshot:run.trace.snapshot} : {}),
      ...(run.explanations?.[output.recommendationNode] ? {recommendation:run.explanations[output.recommendationNode]} : {})} : null;
    panel.innerHTML = `<h2>Пакет данных</h2>${route}<strong class="${delivered ? "studio-confirmed" : ""}">${e(status)}</strong>
      ${delivered ? `<p>${typeNames[portTypes[edge.port]]}</p><pre class="studio-json" tabindex="0">${e(JSON.stringify(payload,null,2))}</pre>` : ""}`;
  }
  function inspect(){
    const n=nodeById(selected);
    if(!n){panel.innerHTML="<h2>Параметры блока</h2><p>Добавьте блок в сценарий.</p>";return;}
    const params=n.params, disabled=canWrite()?"":"disabled";
    let fields="";
    if(n.type==="notify") fields=`<label class="field">Канал<select data-param="channel" ${disabled}>${opts({smtp:"Почта (SMTP)",telegram:"Telegram"},params.channel||"smtp")}</select></label>`;
    if(n.type==="source"){
      const run=getReport(), ref=params.repository||"";
      const key=ref==="@bound"&&legacyBoundId ? "@bound:"+legacyBoundId : ref;
      const choices={"":"Выберите репозиторий"};
      for(const item of repositories)choices["@bound:"+item.bindingId]=item.repository;
      const captured=run?.source;
      if(ref&&captured?.bindingId&&(ref==="@bound"||ref==="@bound:"+captured.bindingId))
        choices[key]=captured.repository;
      const unavailable=key&&!Object.hasOwn(choices,key);
      fields=`<label class="field">Репозиторий расписания<select data-param="repository" ${disabled}>
        ${unavailable?`<option value="${e(key)}" disabled selected>Привязанный репозиторий отключён</option>`:""}
        ${opts(choices,key)}</select></label>`;
      if(!run&&(unavailable||!repositories.length))fields+=unavailable
        ?"<p>Выберите доступный репозиторий или подключите новый в настройках проекта.</p>"
        :"<p>Для своего расписания подключите репозиторий в настройках проекта. Каталог можно загрузить при ручном запуске.</p>";
    }
    if(n.type==="schedule"){
      const zones=new Set([params.timezone||"UTC","UTC",localTimezone(),"Europe/Moscow",...(Intl.supportedValuesOf?.("timeZone")||[])]);
      fields=`<label class="field">Время запуска<input type="time" data-param="time" value="${e(params.time)}" ${disabled}></label>
        <label class="field">Часовой пояс<input list="studio-timezones" data-param="timezone" value="${e(params.timezone||"UTC")}" ${disabled} required></label>
        <datalist id="studio-timezones">${[...zones].sort().map(z=>`<option value="${e(z)}"></option>`).join("")}</datalist>`;
    }
    if (["sast","sca","secrets"].includes(n.type)) {
      fields = `<label class="field">Папка проверки<input data-param="directory" maxlength="250" placeholder="Весь репозиторий" value="${e(params.directory || "")}" ${disabled}>
        <small>Путь от корня проекта, например src/main.</small></label>`;
      if (n.type==="sast") fields += `<label class="field">Проверять файлы<select data-param="language" ${disabled}>
        ${opts({"":"Все поддерживаемые",kotlin:"Kotlin и настройки Spring (.properties)",python:"Python",json:"JSON"},params.language || "")}</select></label>`;
      if (n.type==="sca") fields += `<label class="field">Манифесты зависимостей<select data-param="manifest" ${disabled}>
        ${opts({"":"Gradle и Maven",gradle:"Gradle Kotlin DSL",maven:"Maven"},params.manifest || "")}</select></label>`;
    }
    if (n.type==="explain") {
      fields = `<label class="field">Пояснения<select data-param="mode" ${disabled}>
        ${opts({project:"Сервер модели проекта",catalog:"Офлайн-каталог"}, params.mode || "project")}</select></label>`;
      if (params.mode!=="catalog") fields += `<label class="field">Модель этого шага<input data-param="model" maxlength="128" value="${e(params.model || "")}" placeholder="Модель проекта" ${disabled}>
        <small>Можно указать ID другой модели на подключённом сервере.</small></label>`;
    }
    if (n.type==="regex") {
      const connected = graph().edges.some(edge => edge.to === n.id && edge.input === "values");
      const rows = params.values || [];
      fields = `<label class="field">Регулярное выражение<input data-param="pattern" maxlength="128" required spellcheck="false" value="${e(params.pattern || "")}" placeholder="Например, \\.py$" ${disabled}></label>
        <fieldset class="studio-string-list" ${disabled || (connected ? "disabled" : "")}><legend>Строки для проверки</legend>
        ${connected ? "<p>Список приходит на вход «Строки» по связи.</p>" : ""}
        ${rows.map((v,i) => `<div class="studio-string-row"><input aria-label="Строка ${i+1}" data-value-index="${i}" maxlength="1024" value="${e(v)}"><button type="button" class="studio-del" data-remove-value="${i}" aria-label="Удалить строку ${i+1}">×</button></div>`).join("")}
        ${canWrite() && !connected ? `<button type="button" class="button" data-add-value ${rows.length >= 256 ? "disabled" : ""}>Добавить строку</button>` : ""}</fieldset>`;
    }
    if(n.type==="condition"){
      const wired = graph().edges.find(edge => edge.to === n.id && ["found","count"].includes(edge.input))?.input;
      const ops=params.field==="path"?{eq:"Равно",regex:"Регулярное выражение"}:params.field==="category"?{eq:"Равно"}:{gte:"Не меньше",eq:"Равно"};
      fields=`<label class="field">Поле<select data-param="field" ${disabled || (wired ? "disabled" : "")}>${opts({count:"Количество",severity:"Важность",path:"Путь файла",category:"Категория находки"},params.field)}</select></label>
      <label class="field">Сравнение<select data-param="op" ${disabled}>${opts(ops,params.op)}</select></label>
      <label class="field">Значение${params.field==="category"?`<select data-param="value" ${disabled}>${opts({SECRET:"Секрет",SAST:"Статический анализ",SCA:"Зависимость"},params.value)}</select>`:params.field==="severity"?`<select data-param="value" ${disabled}>${opts({LOW:"Низкая",MEDIUM:"Средняя",HIGH:"Высокая",CRITICAL:"Критическая"},String(params.value).toUpperCase())}</select>`:`<input data-param="value" type="${params.field==="count"?"number":"text"}" min="0" maxlength="512" value="${e(params.value)}" ${disabled}>`}</label>`;
      if (wired === "found") fields = "<p>Вход «Найдено» выбирает ветку «Да» или «Нет».</p>";
      if (wired === "count") fields = "<p>Число приходит на вход «Количество».</p>" + fields;
    }
    displayedResult = nodeResult(getReport(), n, e);
    panel.innerHTML=`<div class="studio-inspector-title"><span class="studio-glyph">${nodeIcon(n.type)}</span><div><h2>${e(labels[n.type])}</h2><small>${e(n.id)}</small></div></div><p>${e(hints[n.type])}</p>
      <div data-node-result-host>${displayedResult}</div>
      <div class="studio-fields">${fields}</div>
      <h3>Связи</h3><ul class="studio-links">${degrees(n.id).map(edge=>`<li><span>${e(edgeTitle(edge))}</span>
      ${canWrite()?`<button type="button" class="studio-del" data-remove-edge="${getGraph().edges.indexOf(edge)}" aria-label="Удалить связь ${e(edge.from)} → ${e(edge.to)}">×</button>`:""}</li>`).join("") || "<li>Связей пока нет.</li>"}</ul>
      ${canWrite()?`<form class="studio-edge-form"><label class="field">Выход<select name="port">${opts(Object.fromEntries(outputPorts(n.type).map(p=>[p,portName[p]+" · "+typeNames[portTypes[p]]])),outputPorts(n.type)[0])}</select></label>
      <label class="field">Куда направить<select name="target" required></select></label>
      <button type="submit" class="button">Соединить</button></form><button type="button" class="link-button studio-delete" data-delete-node>Удалить блок</button>`:""}`;
    refreshTargets();
  }
  function refreshTargets() {
    const form = panel.querySelector(".studio-edge-form");
    if (!form) return;
    const port = form.elements.port.value;
    const choices = graph().nodes.flatMap(node => inputPorts(node.type)
      .filter(input => !connectionError(selected,node.id,port,input))
      .map(input => `<option value="${e(node.id)}" data-target-input="${input}">${e(labels[node.type])} · ${e(node.id)} → ${portName[input]}</option>`));
    form.elements.target.innerHTML = `<option value="">${choices.length ? "Выберите вход блока" : "Нет подходящих входов"}</option>` + choices.join("");
    form.querySelector("button").disabled = !choices.length;
  }
  function select(id, open = false) {
    selected = id; selectedEdge = null;
    plane.querySelector(".selected-edge")?.classList.remove("selected-edge");
    for (const box of plane.querySelectorAll("[data-studio-box]")) {
      const yes = box.dataset.studioBox === id;
      box.classList.toggle("selected", yes);
      box.querySelector(".studio-node-body").setAttribute("aria-pressed", String(yes));
    }
    inspect(); if (open) inspectNode(nodeById(id));
  }
  function structuralError(from,to) {
    if (!from || !to || from.id === to.id) return "Выберите другой блок.";
    if (trigger(to.type) || trigger(from.type) !== (to.type === "source")) return "Соедините триггер с блоком «Репозиторий».";
    if (to.type === "verify" && (from.type !== "explain" || graph().edges.some(edge => edge.to === to.id))) return "Подключите контролёр к одному блоку объяснения ИИ.";
    return "";
  }
  function compatibleInput(node, port) {
    return inputPorts(node.type).find(input => portTypes[input] === portTypes[port]);
  }
  function connectionError(from, to, port, input) {
    const a = nodeById(from), b = nodeById(to);
    const error = structuralError(a,b);
    if (error) return error;
    if (!outputPorts(a.type).includes(port)) return "Этот выход недоступен.";
    input ??= compatibleInput(b,port);
    if (!inputPorts(b.type).includes(input) || portTypes[input] !== portTypes[port]) return "Выберите вход того же типа.";
    const edges = graph().edges;
    if (edges.length >= 128) return "Достигнут предел в 128 связей.";
    if (edges.some(x => x.from === from && x.to === to && x.port === port && (x.input || "in") === input)) return "Эта связь уже существует.";
    if (input !== "in" && edges.some(x => x.to === to && x.input === input)) return "К этому входу уже подключён выход. Сначала удалите прежнюю связь.";
    if (b.type === "condition" && input !== "in") {
      if (edges.some(x => x.to === to && ["count","found"].includes(x.input))) return "Условие принимает либо число, либо ответ «Да / нет».";
      if (input === "count" && b.params.field !== "count") return "В параметрах условия выберите поле «Количество».";
    }
    const reachable = [to], visited = new Set();
    while (reachable.length) {
      const next = reachable.pop();
      if (next === from) return "Связь замкнёт цикл.";
      if (!visited.has(next)) { visited.add(next); reachable.push(...edges.filter(x => x.from === next).map(x => x.to)); }
    }
    return "";
  }
  function clearWire() {
    wire = null; scroller.classList.remove("wiring");
    plane.querySelector(".canvas-preview")?.removeAttribute("d");
    plane.querySelectorAll(".canvas-origin, .canvas-target").forEach(el => el.classList.remove("canvas-origin","canvas-target"));
  }
  function startWire(button) {
    clearWire();
    wire = {from:button.dataset.origin, port:button.dataset.studioPort};
    button.classList.add("canvas-origin"); scroller.classList.add("wiring");
    for (const item of plane.querySelectorAll("[data-studio-input]")) {
      if (!connectionError(wire.from, item.dataset.studioInput, wire.port, item.dataset.inputKey)) item.classList.add("canvas-target");
    }
  }
  function connect(from,to,port,input) {
    if (!canWrite()) return;
    const error = connectionError(from,to,port,input); clearWire();
    if (error) {announce(error,true); return;}
    input ??= compatibleInput(nodeById(to),port);
    graph().edges.push(input === "in" ? {from,to,port} : {from,to,port,input}); selected = to;
    onChange(); draw(); focusNode(to); announce("Блоки соединены.");
  }
  function allowedTypes(origin) {
    if (!canWrite()) return [];
    const nodes = graph().nodes;
    if (!nodes.length) return ["manual","schedule"];
    const keys = Object.keys(labels), from = origin && nodeById(origin.from);
    if (!from) return keys;
    if (graph().edges.length >= 128 || !outputPorts(from.type).includes(origin.port)) return [];
    return keys.filter(type => {
      if (trigger(type)) return false;
      const existing = type === "source" && nodes.find(n => n.type === type);
      if (existing) return !connectionError(from.id,existing.id,origin.port);
      return nodes.length < 48 && !structuralError(from,{type}) && compatibleInput({type},origin.port);
    });
  }
  function addNode(type, origin = null, position = null) {
    if (!canWrite() || !allowedTypes(origin).includes(type)) return;
    const current = graph(), from = origin && nodeById(origin.from);
    const existing = current.nodes.find(n => trigger(type) && trigger(n.type) || type === "source" && n.type === "source");
    if (existing) {
      if (existing.type !== type) {
        existing.type = type; existing.params = type === "schedule" ? {time:"14:00",timezone:localTimezone()} : {};
        onChange(); draw();
      }
      if (from) connect(from.id, existing.id, origin.port);
      ensureVisible(existing); select(existing.id,true); focusNode(existing.id); return;
    }
    if (current.nodes.length >= 48) {announce("Достигнут предел в 48 блоков.",true);return;}
    let suffix = 1, id = type;
    while (nodeById(id)) id = `${type}-${++suffix}`;
    let x = position?.x ?? (from ? from.x + width(from) + 112 : (scroller.clientWidth / 2 - left) / scale - HALF);
    let y = position?.y ?? (from ? from.y + (origin.port === "false" ? 155 : 0) : (scroller.clientHeight / 2 - top) / scale - HALF);
    if (!position) {
      while (current.nodes.some(n => x < n.x + width(n) + 54 && n.x < x + width({type}) + 54
        && y < n.y + height(n) + 52 && n.y < y + height({type}) + 52)) y += height({type}) + 57;
    }
    const params = type === "condition" ? {field:"count",op:"gte",value:1} : type === "regex" ? {pattern:"\\.py$",values:[]} : type === "schedule" ? {time:"14:00",timezone:localTimezone()} : {};
    const node = {id,type,x:clamp(Math.round(x),-100000,100000),y:clamp(Math.round(y),-100000,100000),params};
    current.nodes.push(node);
    if (from) {
      const input = compatibleInput(node,origin.port);
      current.edges.push({from:from.id,to:id,port:origin.port,...(input === "in" ? {} : {input})});
    }
    selected = id; onChange(); draw(); ensureVisible(node); focusNode(id); inspectNode(node);
    announce(from ? "Шаг добавлен и соединён." : "Шаг добавлен.");
  }
  function moveNode(n,x,y) {
    n.x = clamp(Math.round(x),-100000,100000); n.y = clamp(Math.round(y),-100000,100000);
    const box = plane.querySelector(`[data-studio-box="${CSS.escape(n.id)}"]`);
    box.style.left = n.x + "px"; box.style.top = n.y + "px"; drawWires();
  }
  function setParameter(el) {
    const n = nodeById(selected); if (!n || !canWrite()) return;
    const k = el.dataset.param, v = el.value;
    if (k === "field") {
      const defaults = {path:["regex","\\.kt$"], severity:["gte","HIGH"], count:["gte",1], category:["eq","SECRET"]};
      const [op,value] = defaults[v];
      n.params = {field:v, op, value};
      inspect();
    } else if (k === "mode") {
      if (v === "catalog") {n.params.mode = v; delete n.params.model;}
      else delete n.params.mode;
      inspect();
    } else if (["repository","language","manifest","directory","model"].includes(k)) {
      if (v.trim()) n.params[k] = v.trim();
      else delete n.params[k];
    }
    else n.params[k] = k === "value" && n.params.field === "count" && v !== "" ? Number(v) : v;
    onChange();
    if (n.type === "schedule" || n.type === "notify") {
      const body = plane.querySelector(`[data-studio-node="${CSS.escape(n.id)}"]`);
      body.querySelector("small").textContent = subtitle(n); body.title = title(n.id) + " · " + subtitle(n);
    }
    if (k === "repository") inspect();
  }
  section.addEventListener("click", event => {
    if (suppressClick && event.detail > 0 && scroller.contains(event.target)) {suppressClick = false; return;}
    const button = event.target.closest("button"), edge = event.target.closest("[data-inspect-edge]");
    if (edge) {clearWire(); inspectPacket(Number(edge.dataset.inspectEdge)); onInspect(); return;}
    if (button?.hasAttribute("data-studio-fit")) {fit();return;}
    if (button?.hasAttribute("data-zoom")) {zoom(Number(button.dataset.zoom) < 0 ? 1 / 1.25 : 1.25);return;}
    if (button?.hasAttribute("data-add-after") && canWrite()) {
      clearWire(); onAddRequest?.({from:button.dataset.addAfter,port:button.dataset.afterPort}); return;
    }
    if (button?.hasAttribute("data-studio-port") && canWrite()) {
      startWire(button); announce("Выберите вход следующего шага. Escape отменяет связь."); return;
    }
    if (button?.hasAttribute("data-studio-input")) {
      if (wire && canWrite()) connect(wire.from,button.dataset.studioInput,wire.port,button.dataset.inputKey);
      else select(button.dataset.studioInput,true);
      return;
    }
    if (button?.hasAttribute("data-studio-node")) {
      if (wire && canWrite()) connect(wire.from,button.dataset.studioNode,wire.port);
      else select(button.dataset.studioNode,true);
      return;
    }
    if (scroller.contains(event.target)) clearWire();
    if (!canWrite()) return;
    if (button?.matches("[data-add-value],[data-remove-value]")) {
      const n = nodeById(selected);
      if (n?.type !== "regex") return;
      const rows = n.params.values ||= [];
      const adding = button.hasAttribute("data-add-value");
      if (adding && rows.length < 256) rows.push("");
      else if (!adding) rows.splice(Number(button.dataset.removeValue),1);
      onChange(); inspect();
      const index = adding ? rows.length - 1 : Math.min(Number(button.dataset.removeValue),rows.length - 1);
      (panel.querySelector(`[data-value-index="${index}"]`) || panel.querySelector("[data-add-value]"))?.focus();
      return;
    }
    if (button?.hasAttribute("data-delete-node")) {
      const current = graph();
      current.nodes = current.nodes.filter(n => n.id !== selected);
      current.edges = current.edges.filter(x => x.from !== selected && x.to !== selected);
      onChange(); draw(); return;
    }
    if (button?.hasAttribute("data-remove-edge")) {
      graph().edges.splice(Number(button.dataset.removeEdge),1); onChange(); draw(); announce("Связь удалена.");
    }
  });
  section.addEventListener("submit", event => {
    if (!event.target.matches(".studio-edge-form")) return;
    event.preventDefault();
    const values = new FormData(event.target);
    connect(selected,values.get("target"),values.get("port"),event.target.elements.target.selectedOptions[0]?.dataset.targetInput);
  });
  panel.addEventListener("change", event => {
    const el = event.target;
    if (el.matches(".studio-edge-form [name=port]")) refreshTargets();
    if (el.matches("[data-param]")) setParameter(el);
    if (el.matches("[data-value-index]") && canWrite()) {
      nodeById(selected).params.values[Number(el.dataset.valueIndex)] = el.value;
      onChange();
    }
  });
  scroller.addEventListener("keydown", event => {
    if (event.key === "Escape" && wire) {
      const origin = wire.from; clearWire(); focusNode(origin); event.stopPropagation(); return;
    }
    const edge = event.target.closest("[data-inspect-edge]");
    if (edge && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault(); inspectPacket(Number(edge.dataset.inspectEdge)); onInspect(); return;
    }
    const key = event.key;
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (["+", "=", "-", "_", "1", "0"].includes(key)) {
      event.preventDefault();
      if (key === "1") fit(); else zoom(key === "0" ? 1 / scale : (key === "-" || key === "_") ? .8 : 1.25);
      return;
    }
    const delta = {ArrowLeft:[-1,0],ArrowRight:[1,0],ArrowUp:[0,-1],ArrowDown:[0,1]}[key];
    if (!delta) return;
    const body = event.target.closest("[data-studio-node]");
    if (!body && event.target !== scroller) return;
    event.preventDefault(); autoFit = false;
    if (!body || !canWrite()) {left -= delta[0] * 70; top -= delta[1] * 70; applyView(); return;}
    const n = nodeById(body.dataset.studioNode), step = event.shiftKey ? 40 : 10;
    moveNode(n,n.x + delta[0] * step,n.y + delta[1] * step);
    ensureVisible(n); onChange();
  });
  scroller.addEventListener("wheel", event => {
    event.preventDefault();
    const unit = event.deltaMode === 1 ? 18 : event.deltaMode === 2 ? scroller.clientHeight : 1;
    if (event.ctrlKey || event.metaKey) {
      const rect = scroller.getBoundingClientRect();
      zoom(Math.exp(-clamp(event.deltaY * unit,-200,200) * .008),event.clientX - rect.left,event.clientY - rect.top);
    } else {
      autoFit = false; left -= (event.shiftKey ? event.deltaY : event.deltaX) * unit;
      top -= (event.shiftKey ? event.deltaX : event.deltaY) * unit; applyView();
    }
  }, {passive:false});
  scroller.addEventListener("dblclick", event => {
    if (event.target.closest("button,[data-inspect-edge]")) return;
    const rect = scroller.getBoundingClientRect();
    zoom(Math.max(.86 / scale, 1.5),event.clientX - rect.left,event.clientY - rect.top);
  });
  scroller.addEventListener("pointerdown", event => {
    if (gesture || ![0,1].includes(event.button)) return;
    suppressClick = false;
    const target = event.target, port = target.closest("[data-studio-port]"), body = target.closest("[data-studio-node]");
    const pan = event.button === 1 || event.ctrlKey || event.metaKey || !target.closest("button,[data-inspect-edge]");
    const details = {pointer:event.pointerId,x:event.clientX,y:event.clientY,moved:false};
    if (pan) {
      clearWire(); gesture = {...details,mode:"pan",left,top}; scroller.setPointerCapture(event.pointerId);
      scroller.classList.add("panning"); event.preventDefault();
    } else if (port && canWrite()) {
      startWire(port); gesture = {...details,mode:"wire"}; port.setPointerCapture(event.pointerId);
    } else if (body && canWrite() && !wire) {
      const node = nodeById(body.dataset.studioNode);
      gesture = {...details,mode:"node",node,originX:node.x,originY:node.y}; body.setPointerCapture(event.pointerId);
    }
  });
  scroller.addEventListener("pointermove", event => {
    const g = gesture;
    if (!g || g.pointer !== event.pointerId) return;
    const dx = event.clientX - g.x, dy = event.clientY - g.y;
    if (!g.moved && Math.hypot(dx,dy) < 4) return;
    g.moved = true;
    if (g.mode === "pan") {autoFit = false; left = g.left + dx; top = g.top + dy; applyView();}
    if (g.mode === "node" && canWrite()) {autoFit = false; moveNode(g.node,g.originX + dx / scale,g.originY + dy / scale);}
    if (g.mode === "wire" && wire) {
      const origin = nodeById(wire.from), end = world(event.clientX,event.clientY);
      plane.querySelector(".canvas-preview").setAttribute("d",curve(origin.x + width(origin),origin.y + portY(origin,wire.port),end.x,end.y));
    }
  });
  function finishGesture(event) {
    if (!gesture || gesture.pointer !== event.pointerId) return;
    const {mode,moved} = gesture; gesture = null; scroller.classList.remove("panning");
    if (mode === "node" && moved) onChange();
    if (moved) {suppressClick = true; setTimeout(() => {suppressClick = false;}, 0);}
    if (mode !== "wire") return;
    if (event.type === "pointercancel" || !wire) {clearWire();return;}
    if (!moved) return;
    const drop = document.elementFromPoint(event.clientX,event.clientY)?.closest("[data-studio-input], [data-studio-node]");
    if (drop && plane.contains(drop)) connect(wire.from,drop.dataset.studioInput || drop.dataset.studioNode,wire.port,drop.dataset.inputKey);
    else clearWire();
  }
  scroller.addEventListener("pointerup",finishGesture);
  scroller.addEventListener("pointercancel",finishGesture);
  section.addEventListener("dragstart", event => {
    const button = event.target.closest("[data-picker-type],[data-add-type]");
    if (button && canWrite()) event.dataTransfer.setData("application/x-studio-node",button.dataset.pickerType || button.dataset.addType);
  });
  scroller.addEventListener("dragover", event => {
    if (canWrite() && event.dataTransfer.types.includes("application/x-studio-node")) event.preventDefault();
  });
  scroller.addEventListener("drop", event => {
    const type = event.dataTransfer.getData("application/x-studio-node"); if (!type || !canWrite()) return;
    event.preventDefault(); const pos = world(event.clientX,event.clientY);
    addNode(type,getAddOrigin(),{x:pos.x - HALF,y:pos.y - HALF});
  });
  const observer = new ResizeObserver(() => {if (autoFit && graphRef) fit(false);});
  observer.observe(scroller);
  function statuses(stages) {
    if (getReport()) {
      drawWires();
      if (selectedEdge != null) inspectPacket(selectedEdge);
      else {
        const host = panel.querySelector("[data-node-result-host]"), node = nodeById(selected);
        if (host && node) {
          const markup = nodeResult(getReport(), node, e);
          if (markup !== displayedResult) {
            const open = [...host.querySelectorAll("details")].map(el => el.open);
            host.innerHTML = displayedResult = markup;
            host.querySelectorAll("details").forEach((el,i) => el.open = !!open[i]);
          }
        }
      }
    }
    const byId = new Map((stages || []).map(stage => [stage.id,stage.status]));
    for (const box of plane.querySelectorAll("[data-studio-box]")) {
      const status = byId.get(box.dataset.studioBox); box.querySelector(".studio-live")?.remove();
      if (!status) continue;
      const badge = document.createElement("span"); badge.className = "studio-live"; badge.dataset.status = status;
      badge.textContent = ({done:"Готово",running:"В работе",skipped:"Пропущен",error:"Ошибка"})[status] || status;
      box.append(badge);
    }
  }
  return {draw,fit,addNode,allowedTypes,statuses,dispose:() => observer.disconnect()};
}
