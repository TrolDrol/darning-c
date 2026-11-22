import {nodeResult} from "/studio_node_result.js";
import {stageStatus} from "/studio_report.js";
import {customDefaults,customFields,exportDefinition,importDefinition,changeStep} from "/studio_custom.js";
import {inputPorts, outputPorts, portNames as portName, portTypes, typeNames, triggerTypes} from "/studio_ports.js";

export const labels = {
  dependency_review:"Зависимости PR",
  github_actions:"GitHub Actions",
  dockerfile:"Dockerfile",
  java_review:"Ревью Java",
  spring_review:"Безопасность Spring и JVM",
  spring_routes:"Маршруты Spring",
  package_review:"Зависимости npm и PyPI",
  literal_review:"Текстовое правило",
  model_load:"Загрузка модели",
  "ai_review": "ИИ-обзор · эксперимент",
  "manual": "Ручной запуск",
  "schedule": "Расписание",
  "github_pr": "Pull request",
  "github_push": "Push в GitHub",
  "webhook": "HTTP-вебхук",
  "source": "Репозиторий",
  "secrets": "Поиск секретов",
  "sca": "Зависимости",
  "sast": "Анализ кода",
  "regex": "Поиск по Regex",
  "custom": "Своя нода",
  "json_keys": "Повтор ключей JSON",
  "condition": "Условие",
  "explain": "Объяснение ИИ",
  "verify": "Контроль фактов",
  "notify": "Оповещение"
};

export function localTimezone(){return Intl.DateTimeFormat().resolvedOptions().timeZone || "Europe/Moscow";}

const TILE = 72;
const HALF = TILE / 2;
const trigger = type => triggerTypes.includes(type);
const expanded = node => ["source","condition","regex","custom","model_load","explain","ai_review"].includes(node.type);
const width = node => expanded(node) ? 178 : TILE;
const extraHeaderHeight = node => node.type === "model_load" ? 17 : 0;
const height = node => expanded(node)
  ? 52 + extraHeaderHeight(node) + 26 * Math.max(inputPorts(node.type).length,outputPorts(node.type).length)
  : TILE;
// Unscaled bounds include the 166px caption, socket hit areas, "+" and status badge.
function bounds(node, x = node.x, y = node.y) {
  return {left:x - (expanded(node) ? 12 : 47), right:x + width(node) + (expanded(node) ? 40 : 47),
    top:y - 14, bottom:y + height(node) + (expanded(node) ? 0 : 64)};
}
const COLUMN_GAP = 48, ROW_GAP = 34;
const SOCKET = "[data-studio-port],[data-studio-input]";

function socketRef(element) {
  const {studioInput,inputKey,origin,studioPort} = element.dataset;
  return studioInput ? {id:studioInput,port:inputKey,side:"input"} : {id:origin,port:studioPort,side:"output"};
}

function defaults(type) {
  if (type === "condition") return {field:"count",op:"gte",value:1};
  if (type === "regex") return {pattern:"\\.py$",values:[]};
  if (type === "schedule") return {time:"14:00",timezone:localTimezone()};
  return type === "custom" ? customDefaults() : {};
}

function templatePositions(nodes) {
  const original = {manual:[40,160],schedule:[40,160],source:[240,160],secrets:[440,30],sca:[440,160],
    sast:[440,290],explain:[650,160],verify:[850,160],condition:[1050,160],notify:[1260,160]};
  const isDefault = nodes.length === 9 && nodes.every(n => {
    const position = original[trigger(n.type) ? "manual" : n.type];
    return position && n.x === position[0] && n.y === position[1];
  });
  const isPreset = nodes.every((n,i) => n.x === i * 180 && n.y === 60);
  const isGenerated = nodes.every((n,i) => n.x === 60 + i * 215 && n.y === 100);
  if (!isDefault && !isPreset && !isGenerated) return new Map();
  function space(axis, start, end, gap) {
    const positions = new Map();
    let previousEnd = -Infinity;
    for (const original of [...new Set(nodes.map(n => n[axis]))].sort((a,b) => a-b)) {
      const extents = nodes.filter(n => n[axis] === original).map(n => bounds(n,0,0));
      const at = Math.max(original, previousEnd + gap - Math.min(...extents.map(rect => rect[start])));
      positions.set(original,at);
      previousEnd = at + Math.max(...extents.map(rect => rect[end]));
    }
    return positions;
  }
  const cols = space("x","left","right",COLUMN_GAP), rows = space("y","top","bottom",ROW_GAP);
  return new Map(nodes.map(n => [n.id,{x:cols.get(n.x),y:rows.get(n.y)}]));
}
const portY = (node,port,input = false) => expanded(node)
  ? 54 + extraHeaderHeight(node) + 26 * (input ? inputPorts : outputPorts)(node.type).indexOf(port) : HALF;
const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
const subtitles = {manual:"По кнопке", github_pr:"Обновление PR", github_push:"Обновление ветки", webhook:"Команда CI/CD", source:"Снимок файлов", secrets:"Текстовые файлы", sca:"Gradle / Maven",
  dependency_review:"Изменения в PR", github_actions:"Права и версии", dockerfile:"Пользователь образа", java_review:"Качество кода",
  spring_review:"Настройки и вызовы", package_review:"Файлы зависимостей", literal_review:"Поиск по строкам",
  spring_routes:"Обработчики и доступ",
  ai_review:"Статические признаки кода",
  sast:"По типу файла", regex:"Регулярное выражение", condition:"Если / иначе", explain:"Рекомендации", verify:"Доказательства", notify:"Почта"};
const hints = {manual:"Запускает проверку по кнопке.", schedule:"Запускает сохранённый сценарий в выбранные дни по местному времени указанного часового пояса.",
  dependency_review:"Сравнивает прямые зависимости Gradle и Maven между общей базой веток и проверяемым коммитом. Выберите триггер Pull request или передайте baseRevision и revision через HTTP-вебхук.",
  github_actions:"Читает YAML GitHub Actions. Отмечает избыточные разрешения токена и внешние действия без фиксированного коммита.",
  dockerfile:"Определяет пользователя финального этапа сборки Docker. Если пользователь зависит от внешнего образа или аргумента сборки, указывает ограничение проверки.",
  java_review:"Ищет в Java повторяющиеся условия, длинные методы и конструкции для проверки производительности. Влияние на скорость подтвердите измерением на своих данных.",
  github_pr:"Выберите репозиторий в следующем блоке и включите сценарий. Открытие, повторное открытие, смена базовой ветки или обновление PR внутри репозитория запустит проверку коммита из PR.",
  github_push:"Выберите репозиторий в следующем блоке и включите сценарий. Каждый push в ветку запустит проверку полученного коммита.",
  webhook:"Включите сценарий и отправьте команду из CI с ключом проекта, идентификатором сценария, репозиторием и SHA коммита.",
  model_load:"Соедините «Далее» репозитория со входом «Поток» этого шага, а выход «Модель» со входом «Модель» шага ИИ. На шаг ИИ также подайте его обычный поток данных.",
  ai_review:"Ищет подавленные исключения и изменяемые аргументы по умолчанию. Модель предлагает, что перепроверить.",
  custom:"Применяет ваши операции к списку сверху вниз. На выходах доступны оставшиеся строки, их число и признак непустого результата. Определение можно скачать и загрузить в другой сценарий.",
  json_keys:"Сравнивает декодированные имена ключей отдельно в каждом JSON-объекте. Возвращает строку и столбец повтора. Одинаковые имена в разных объектах допустимы.",
  source:"Принимает снимок репозитория, папку или архив проекта.", secrets:"Ищет признаки встроенных учётных данных в тексте.",
  sca:"Сверяет зависимости Maven, Gradle и записи Gradle lockfile со справочником.", sast:"Проверяет Python, JSON, Kotlin, JavaScript, TypeScript и настройки Spring.",
  spring_review:"Проверяет выдачу трассировок, отключение CSRF, слабые хеши и прямую передачу параметра Spring-маршрута в строку JPA-запроса.",
  spring_routes:"Перечисляет объявленные в Kotlin маршруты и обработчики Spring. Показывает явную аннотацию доступа метода или неизвестный статус.",
  package_review:"Сверяет package-lock.json и точные версии из requirements.txt со справочником npm и PyPI.",
  literal_review:"Ищет заданный текст в строках файлов. В находке сохраняются путь и координаты.",
  regex:"Ищет совпадения в каждой строке. Соедините выход с подходящим входом другого блока.",
  condition:"Выбирает ветку для всего набора найденных замечаний.", explain:"Группирует находки и готовит рекомендации по исправлению.",
  verify:"Сверяет заявленный моделью тип риска, число находок и координаты со снимком запуска.", notify:"Отправляет сводку через выбранный канал проекта."};
const recipientHints = {
  smtp:"Руководитель выбирает адрес для автоматических запусков через <a href=\"#projects\">Проекты → Участники</a> → «Получатель SMTP». При ручном запуске письмо приходит на подтверждённую почту инициатора. Общий адрес, назначенный оператором, имеет приоритет.",
  webhook:"Отправляет сводку и ссылку на отчёт на HTTPS-адрес, который оператор назначил проекту. Ключ CI/CD нужен для отдельного начального шага «HTTP-вебхук», который принимает команду запуска."
};
const symbols = {
  github_actions:'<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="12" r="2.5"/><circle cx="5" cy="18" r="2.5"/><path d="M7.5 6h3l4 6h2m-9 6h3l4-6"/>',
  dependency_review:'<circle cx="5" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><path d="M5 7v10m6-7 3 3 6-7"/>',
  dockerfile:'<path d="m12 2 9 5v10l-9 5-9-5V7Zm-9 5 9 5 9-5m-9 5v10"/>',
  spring_review:'<path d="M12 3 5 6v5c0 4 3 7 7 10 4-3 7-6 7-10V6zM9 12l2 2 4-4"/>',
  spring_routes:'<circle cx="6" cy="5" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="12" cy="19" r="2"/><path d="M6 7v3l6 4 6-4V7m-6 7v3"/>',
  package_review:'<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9zm-8 4.5 8 4.6 8-4.6M12 12v9"/>',
  literal_review:'<path d="M4 7h13M4 12h8M4 17h6m7-1 4 4"/><circle cx="16" cy="13" r="3"/>',
  java_review:'<path d="M4 10h12v4a6 6 0 0 1-12 0Zm12 1h2a2 2 0 0 1 0 4h-2M3 21h15M7 7c3-2-2-2 1-5m4 5c3-2-2-2 1-5"/>',
  github_pr:'<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="19" r="2"/><path d="M6 7v10m12 0v-5a6 6 0 0 0-6-6h-1m3-3-3 3 3 3"/>',
  github_push:'<path d="M12 16V3m-5 5 5-5 5 5M4 15v5h16v-5"/>',
  webhook:'<path d="m8 9 4 6m5-6-4 6M8 18h8"/><circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/>',
  model_load:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3"/><path d="m10 12 1.5 1.5L14 11"/>',
  ai_review:'<path d="M9 3h6m-5 0v6l-6 10a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2L14 9V3m-6 12h8"/>',
  manual:'<path d="M8 4.5 20 12 8 19.5z"/>', schedule:'<circle cx="12" cy="12" r="8.3"/><path d="M12 7v5l3.4 1.8"/>',
  source:'<path d="M3.5 6.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/><path d="m10 10.5-2.5 2.3 2.5 2.3m4-4.6 2.5 2.3-2.5 2.3"/>',
  secrets:'<circle cx="9" cy="10" r="4.8"/><path d="m12.5 13.5 6.2 6.2m-2.5-2.5 2.1-2.1m-4.3-.1 2.1-2.1"/>',
  sca:'<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9zm-8 4.5 8 4.6 8-4.6M12 12v9m-4-16 8 4.6"/>',
  sast:'<path d="m7.8 7.2-4.9 4.9 4.9 4.8m8.4-9.7 4.9 4.9-4.9 4.8m-2.1-12.7-4 15.3"/>',
  regex:'<circle cx="5" cy="18" r="1.4"/><path d="M15 4v12m-5-9 10 6M10 13l10-6"/>',
  custom:'<path d="M3 7h18M3 17h18"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
  json_keys:'<path d="M9 4H6v5l-2 3 2 3v5h3m6-16h3v5l2 3-2 3v5h-3"/>',
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
    canWrite, escape:e, onChange, announce, onAddRequest, modelConnections = [], manageModels = false,
    getAddOrigin = () => null, onInspect = () => {}, onManageModels}) {
  const scroller = section.querySelector(".studio-scroller");
  const plane = section.querySelector(".studio-plane");
  const panel = section.querySelector(".studio-inspector");
  scroller.classList.add("automation-canvas");
  scroller.title = "Перетащите фон, чтобы переместить схему. Ctrl + колесо меняет масштаб. Клавиша 1 вписывает граф.";
  let selected, selectedEdge, graphRef, gesture, wire, suppressClick = false, displayedResult = "";
  let scale = 1, left = 0, top = 0, autoFit = true, fullOverview = false;
  const graph = getGraph;
  const nodeById = id => graph().nodes.find(n => n.id === id);
  let positions = new Map();
  const placed = node => positions.has(node.id) ? {...node,...positions.get(node.id)} : node;
  function commitPositions() {
    if (!positions.size) return;
    for (const node of graph().nodes) Object.assign(node,positions.get(node.id));
    positions.clear();
  }
  const degrees = id => graph().edges.filter(edge => edge.from === id || edge.to === id);
  const title = id => {const node=nodeById(id);return (node?.type==="custom" && node.params.name) || labels[node?.type] || id;};
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
    const nodes = graph().nodes.map(placed), w = scroller.clientWidth, h = scroller.clientHeight;
    if (!w || !h) return;
    const rects = nodes.map(node => bounds(node));
    const x = nodes.length ? Math.min(...rects.map(r => r.left)) : 0, y = nodes.length ? Math.min(...rects.map(r => r.top)) : 0;
    const endX = nodes.length ? Math.max(...rects.map(r => r.right)) : TILE;
    const endY = nodes.length ? Math.max(...rects.map(r => r.bottom)) : TILE;
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
    node = placed(node);
    const w = scroller.clientWidth, h = scroller.clientHeight;
    const x = left + (node.x + width(node)/2) * scale, y = top + (node.y + height(node)/2) * scale;
    if (x >= 60 && x <= w - 60 && y >= 54 && y <= h - 100) return;
    left += w / 2 - x; top += (h - 56) / 2 - y; autoFit = false; applyView();
  }
  function inspectNode(node) {
    node = placed(node);
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
      const from = nodeById(edge.from), to = nodeById(edge.to);
      if (!from || !to) return "";
      const a = placed(from), b = placed(to);
      const d = curve(a.x + width(a) + 5, a.y + portY(a, edge.port), b.x - 9, b.y + portY(b, edge.input || "in", true));
      const active = sent(run?.trace?.outputs?.[a.id],edge.port);
      const label = edgeTitle(edge);
      const wireClass = {false:"otherwise",model:"model-link"}[edge.port] || "";
      return `<g class="studio-edge ${active ? "taken" : ""} ${selectedEdge === i ? "selected-edge" : ""}" data-inspect-edge="${i}" tabindex="0" role="button" aria-label="${e(label)}">
        <path class="studio-hit" d="${d}"/><path class="studio-wire ${wireClass}" d="${d}" marker-end="url(#studio-arrow-${active ? "used" : "normal"})"/></g>`;
    });
    const svg = plane.querySelector(".canvas-wires"), focused = document.activeElement?.dataset?.inspectEdge;
    svg.innerHTML = `<defs>${markup.join("")}</defs>${paths.join("")}<path class="canvas-preview" fill="none"/>`;
    if (focused !== undefined) svg.querySelector(`[data-inspect-edge="${CSS.escape(focused)}"]`)?.focus({preventScroll:true});
  }
  function subtitle(n) {
    if (n.type === "custom") return "Операций · " + n.params.steps.length;
    if (n.type === "json_keys") return "Объекты JSON";
    if (n.type === "schedule") return (Object.hasOwn(n.params,"cron")?"Cron":n.params.time || "00:00") + " " + (n.params.timezone || "UTC").split("/").pop();
    if (n.type === "notify") return {telegram:"Telegram",webhook:"HTTP-вебхук"}[n.params.channel] || subtitles[n.type];
    if (n.type === "model_load") return [n.params.connection,n.params.model].filter(Boolean).join(" · ") || "Модель проекта";
    return subtitles[n.type];
  }
  function refreshSubtitle(n) {
    const body = plane.querySelector(`[data-studio-node="${CSS.escape(n.id)}"]`);
    if (!body) return;
    body.querySelector("small").textContent = subtitle(n);
    body.title = title(n.id) + " · " + subtitle(n);
    if (n.type === "model_load") body.setAttribute("aria-label", title(n.id) + " · " + subtitle(n) + ", " + n.id);
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
    const add = canWrite() && onAddRequest && allowedTypes({id:n.id,port,side:"output"}).length ? `<button type="button" class="canvas-next" data-add-after="${e(n.id)}" data-after-port="${port}" aria-label="Добавить шаг после «${e(title(n.id))}», ${portName[port]}">+</button>` : "";
    return `<div class="canvas-outlet ${used ? "has-edge" : "open"}" data-port="${port}" ${socket}>${anchor}${caption}${add}</div>`;
  }
  function draw(animate = false) {
    const current = graph();
    clearWire();
    if (graphRef !== current) {
      selected = undefined; selectedEdge = null; autoFit = true; fullOverview = false; graphRef = current;
      positions = templatePositions(current.nodes);
    }
    if (!nodeById(selected)) selected = current.nodes[0]?.id;
    selectedEdge = null;
    plane.innerHTML = '<svg class="canvas-wires" aria-label="Связи блоков"></svg>' + current.nodes.map(n => {
      const id = e(n.id), name = e(title(n.id)), chosen = n.id === selected;
      const inlet = inputPorts(n.type).map(p => portMarkup(n,p,true)).join("");
      return `<div class="studio-node ${expanded(n) ? "socket-card" : ""} ${chosen ? "selected" : ""}" data-kind="${n.type}" data-studio-box="${id}">
        <button type="button" class="studio-node-body" data-studio-node="${id}" aria-pressed="${chosen}" title="${name} · ${e(subtitle(n))}" aria-label="${name}${n.type === "model_load" ? " · " + e(subtitle(n)) : ""}, ${id}">
          <span class="canvas-node-icon">${nodeIcon(n.type)}</span><span class="canvas-node-caption"><strong>${name}</strong><small>${e(subtitle(n))}</small></span>
        </button>${inlet}${outputPorts(n.type).map(p => portMarkup(n,p)).join("")}</div>`;
    }).join("");
    for (const box of plane.querySelectorAll("[data-studio-box]")) {
      const node = placed(nodeById(box.dataset.studioBox));
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
    const modelInput = graph().edges.find(edge => edge.to === n.id && edge.input === "model");
    function modelSource() {
      const provider = modelInput && nodeById(modelInput.from);
      if (provider) return `<p>Модель поступает по связи · ${e(subtitle(provider))}.</p>`;
      const legacy = [params.connection,params.model].filter(Boolean).join(" · ");
      return `<p>${legacy ? "Модель из сохранённых параметров · " + e(legacy) + "." : "Используется модель проекта."} Подключите шаг «Загрузка модели», чтобы выбрать другую.</p>`;
    }
    let fields="";
    if (n.type==="notify") {
      const channel=params.channel || "smtp";
      fields=`<label class="field">Канал<select data-param="channel" ${Object.hasOwn(recipientHints,channel)?'aria-describedby="studio-'+channel+'-recipient"':""} ${disabled}>
        ${opts({smtp:"Почта (SMTP)",telegram:"Telegram",webhook:"HTTP-вебхук"},channel)}</select></label>
        ${Object.entries(recipientHints).map(([key,text])=>`<p id="studio-${key}-recipient" data-notice-channel="${key}" ${channel===key?"":"hidden"}>${text}</p>`).join("")}`;
    }
    if(n.type==="source"){
      const run=getReport(), ref=params.repository||"";
      const key=ref==="@bound"&&legacyBoundId ? "@bound:"+legacyBoundId : ref;
      const entry = graph().nodes.find(node => trigger(node.type))?.type;
      const choices={"":entry==="webhook"?"Репозиторий из запроса":"Выберите репозиторий"};
      for(const item of repositories)choices["@bound:"+item.bindingId]=item.repository;
      const captured=run?.source;
      if(ref&&captured?.bindingId&&(ref==="@bound"||ref==="@bound:"+captured.bindingId))
        choices[key]=captured.repository;
      const unavailable=key&&!Object.hasOwn(choices,key);
      fields=`<label class="field">Источник сценария<select data-param="repository" ${disabled}>
        ${unavailable?`<option value="${e(key)}" disabled selected>Привязанный репозиторий отключён</option>`:""}
        ${opts(choices,key)}</select></label>`;
      if(!run&&(unavailable||!repositories.length))fields+="<p>Подключите репозиторий в разделе «Проекты → Репозитории».</p>";
    }
    if(n.type==="schedule"){
      const zones=new Set([params.timezone||"UTC","UTC",localTimezone(),"Europe/Moscow",...(Intl.supportedValuesOf?.("timeZone")||[])]);
      const period=Object.hasOwn(params,"cron")?"cron":params.weekdays?"weekly":params.monthDay?"monthly":"daily";
      fields=`${period==="cron"?`<label class="field">Выражение cron<input data-param="cron" maxlength="120" value="${e(params.cron)}" ${disabled}>
        <small>Минута, час, число месяца, месяц и день недели. Например, 15 9 * * MON,WED,FRI.</small></label>`:
        `<label class="field">Время запуска<input type="time" data-param="time" value="${e(params.time)}" ${disabled}></label>`}
        <label class="field">Часовой пояс<input list="studio-timezones" data-param="timezone" value="${e(params.timezone||"UTC")}" ${disabled} required></label>
        <datalist id="studio-timezones">${[...zones].sort().map(z=>`<option value="${e(z)}"></option>`).join("")}</datalist>
        <label class="field">Повторять<select data-period ${disabled}>${opts({daily:"Каждый день",weekly:"По дням недели",monthly:"Ежемесячно",cron:"Выражение cron"},period)}</select></label>
        ${period==="weekly"?`<fieldset class="studio-string-list" ${disabled}><legend>Дни недели</legend>${["Пн","Вт","Ср","Чт","Пт","Сб","Вс"].map((day,i)=>`<label><input type="checkbox" data-weekday="${i+1}" ${params.weekdays.includes(i+1)?"checked":""}> ${day}</label>`).join("")}</fieldset>`:""}
        ${period==="monthly"?`<label class="field">Число месяца<input type="number" data-param="monthDay" min="1" max="31" value="${params.monthDay}" ${disabled}><small>Если такого числа в месяце нет, запуск пропускается.</small></label>`:""}`;
    }
    if (["sast","sca","secrets","json_keys","github_actions","dockerfile","dependency_review","java_review","spring_review","spring_routes","package_review","literal_review"].includes(n.type)) {
      fields = `<label class="field">Папка проверки<input data-param="directory" maxlength="250" placeholder="Весь репозиторий" value="${e(params.directory || "")}" ${disabled}>
        <small>Путь от корня проекта, например src/main.</small></label>`;
      if (n.type==="sast") fields += `<label class="field">Проверять файлы<select data-param="language" ${disabled}>
        ${opts({"":"Все поддерживаемые",kotlin:"Kotlin и настройки Spring (.properties)",python:"Python",javascript:"JavaScript и TypeScript",json:"JSON"},params.language || "")}</select></label>`;
      if (["sca","dependency_review"].includes(n.type)) fields += `<label class="field">Манифесты зависимостей<select data-param="manifest" ${disabled}>
        ${opts({"":"Gradle и Maven",gradle:"Gradle Kotlin DSL",maven:"Maven"},params.manifest || "")}</select></label>`;
    }
    if (n.type === "literal_review") fields += `
      <label class="field">Название правила<input data-param="name" maxlength="100" value="${e(params.name || "")}" ${disabled}></label>
      <label class="field">Текст для поиска<input data-param="literal" maxlength="500" value="${e(params.literal || "")}" ${disabled}>
        <small>Текст сохраняется в сценарии. Используйте общедоступные значения.</small></label>
      <label class="field">Расширение<input data-param="suffix" maxlength="32" value="${e(params.suffix || "")}" placeholder=".properties" ${disabled}></label>
      <label><input type="checkbox" data-param="caseSensitive" ${params.caseSensitive!==false?"checked":""} ${disabled}> Учитывать регистр</label>
      <label class="field">Важность<select data-param="severity" ${disabled}>
        ${opts({low:"Низкая",medium:"Средняя",high:"Высокая",critical:"Критическая"},params.severity || "medium")}</select></label>`;
    if (n.type==="model_load") {
      const choices = Object.fromEntries([["","Модель проекта"],...modelConnections.map(name=>[name,name])]);
      if (params.connection && !Object.hasOwn(choices,params.connection)) {
        choices[params.connection] = params.connection + " (недоступно)";
      }
      fields = `<label class="field">Подключение<select data-param="connection" ${disabled}>${opts(choices,params.connection || "")}</select></label>
        ${manageModels && !disabled && onManageModels ? '<button type="button" class="button" data-model-settings>Настроить подключения</button>' : ""}
        <label class="field">ID модели<input data-param="model" maxlength="128" placeholder="Из подключения" value="${e(params.model || "")}" ${disabled}>
        <small>Заполните, если на выбранном сервере нужна другая модель.</small></label>`;
    }
    if (n.type==="ai_review") {
      fields = `<p>Поддерживаются Python, JavaScript, TypeScript, Java, Kotlin и C#. Модель получает типы конструкций, отмеченных в снимке. Предложения требуют проверки человеком.</p>${modelSource()}`;
    }
    if (n.type==="explain") {
      fields = `<label class="field">Пояснения<select data-param="mode" ${disabled || (modelInput ? "disabled" : "")}>
        ${opts({project:"Модель",catalog:"Офлайн-каталог"}, params.mode || "project")}</select></label>`;
      if (params.mode!=="catalog") fields += modelSource();
      if (modelInput && !disabled) fields += "<p>Чтобы выбрать офлайн-каталог, удалите связь со входа «Модель».</p>";
    }
    if (["regex","custom"].includes(n.type)) {
      const connected = graph().edges.some(edge => edge.to === n.id && edge.input === "values");
      const rows = params.values || [];
      fields = (n.type==="custom" ? customFields(params,e,disabled) : `<label class="field">Регулярное выражение<input data-param="pattern" maxlength="128" required spellcheck="false" value="${e(params.pattern || "")}" placeholder="Например, \\.py$" ${disabled}></label>`) + `
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
      <label class="field">Значение${params.field==="category"?`<select data-param="value" ${disabled}>${opts({SECRET:"Секрет",SAST:"Статический анализ",SCA:"Зависимость",QUALITY:"Качество кода",PERF:"Производительность"},params.value)}</select>`:params.field==="severity"?`<select data-param="value" ${disabled}>${opts({LOW:"Низкая",MEDIUM:"Средняя",HIGH:"Высокая",CRITICAL:"Критическая"},String(params.value).toUpperCase())}</select>`:`<input data-param="value" type="${params.field==="count"?"number":"text"}" min="0" maxlength="512" value="${e(params.value)}" ${disabled}>`}</label>`;
      if (wired === "found") fields = "<p>Вход «Найдено» выбирает ветку «Да» или «Нет».</p>";
      if (wired === "count") fields = "<p>Число приходит на вход «Количество».</p>" + fields;
    }
    displayedResult = nodeResult(getReport(), n, e);
    panel.innerHTML=`<div class="studio-inspector-title"><span class="studio-glyph">${nodeIcon(n.type)}</span><div><h2>${e(labels[n.type])}</h2><small>${e(n.id)}</small></div></div><p>${e(hints[n.type])}</p>
      <div data-node-result-host>${displayedResult}</div>
      <details><summary>Входы и выходы</summary><p>Входы · ${inputPorts(n.type).map(p=>portName[p]+" ("+typeNames[portTypes[p]]+")").join(", ")||"запускается триггером"}</p><p>Выходы · ${outputPorts(n.type).map(p=>portName[p]+" ("+typeNames[portTypes[p]]+")").join(", ")}</p></details>
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
    return edgeError({from:nodeById(from),to:nodeById(to),port,input});
  }
  function edgeError({from:a,to:b,port,input}) {
    const error = structuralError(a,b);
    if (error) return error;
    if (!outputPorts(a.type).includes(port)) return "Этот выход недоступен.";
    input ??= compatibleInput(b,port);
    if (!inputPorts(b.type).includes(input) || portTypes[input] !== portTypes[port]) return "Выберите вход того же типа.";
    if (input === "model" && b.type === "explain" && b.params.mode === "catalog") return "Выберите пояснения с моделью в параметрах блока.";
    const edges = graph().edges;
    if (edges.length >= 128) return "Достигнут предел в 128 связей.";
    if (edges.some(x => x.from === a.id && x.to === b.id && x.port === port && (x.input || "in") === input)) return "Эта связь уже существует.";
    if (input !== "in" && edges.some(x => x.to === b.id && x.input === input)) return "К этому входу уже подключён выход. Сначала удалите прежнюю связь.";
    if (b.type === "condition" && input !== "in") {
      if (edges.some(x => x.to === b.id && ["count","found"].includes(x.input))) return "Условие принимает либо число, либо ответ «Да / нет».";
      if (input === "count" && b.params.field !== "count") return "В параметрах условия выберите поле «Количество».";
    }
    if (!a.id || !b.id) return "";
    const reachable = [b.id], visited = new Set();
    while (reachable.length) {
      const next = reachable.pop();
      if (next === a.id) return "Связь замкнёт цикл.";
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
    wire = socketRef(button);
    button.classList.add("canvas-origin"); scroller.classList.add("wiring");
    for (const item of plane.querySelectorAll(SOCKET)) {
      const socket = socketRef(item);
      if (socket.side === wire.side) continue;
      if (!edgeError(edgeFrom(wire,nodeById(socket.id),socket.port))) item.classList.add("canvas-target");
    }
  }
  function edgeFrom(origin, other, otherPort) {
    const fixed = nodeById(origin.id);
    if (origin.side === "output") return {from:fixed,to:other,port:origin.port,input:otherPort ?? compatibleInput(other,origin.port)};
    const port = otherPort ?? outputPorts(other.type).find(key => portTypes[key] === portTypes[origin.port]);
    return {from:other,to:fixed,port,input:origin.port};
  }
  function connectWire(target) {
    const socket = target.matches(SOCKET) ? socketRef(target) : null;
    if (socket?.side === wire.side) {clearWire(); announce("Соедините выход со входом.",true);return;}
    const node = nodeById(socket?.id ?? target.dataset.studioNode);
    const {from,to,port,input} = edgeFrom(wire,node,socket?.port);
    connect(from.id,to.id,port,input);
  }
  function suggest(origin, opener, position) {
    clearWire();
    if (allowedTypes(origin).length) onAddRequest?.(origin,position,opener);
    else announce("Для этого порта нет подходящих шагов.",true);
  }
  function connect(from,to,port,input) {
    if (!canWrite()) return;
    const error = connectionError(from,to,port,input); clearWire();
    if (error) {announce(error,true); return;}
    input ??= compatibleInput(nodeById(to),port);
    addEdge(from,to,port,input); selected = to;
    onChange(); draw(); focusNode(to); announce("Блоки соединены.");
  }
  function addEdge(from,to,port,input) {
    graph().edges.push(input === "in" ? {from,to,port} : {from,to,port,input});
  }
  function allowedTypes(origin) {
    if (!canWrite()) return [];
    const nodes = graph().nodes;
    if (!nodes.length) return triggerTypes;
    const keys = Object.keys(labels);
    if (!origin) return keys;
    const fixed = nodeById(origin.id);
    const ports = origin.side === "input" ? inputPorts : outputPorts;
    if (!fixed || !ports(fixed.type).includes(origin.port) || graph().edges.length >= 128) return [];
    return keys.filter(type => {
      const existing = singleton(type);
      if (existing ? existing.type !== type : nodes.length >= 48) return false;
      return !edgeError(edgeFrom(origin,existing || {type,params:defaults(type)}));
    });
  }
  function singleton(type) {
    if (trigger(type)) return graph().nodes.find(n => trigger(n.type));
    if (type === "source") return graph().nodes.find(n => n.type === "source");
  }
  function addNode(type, origin = null, position = null) {
    if (!canWrite() || !allowedTypes(origin).includes(type)) return;
    const current = graph(), existing = singleton(type);
    const fixed = origin && nodeById(origin.id);
    if (existing) {
      if (existing.type !== type) {
        existing.type = type; existing.params = defaults(type);
        onChange(); draw();
      }
      if (origin) {
        const {from,to,port,input} = edgeFrom(origin,existing);
        connect(from.id,to.id,port,input);
      }
      ensureVisible(existing); select(existing.id,true); focusNode(existing.id); return;
    }
    if (current.nodes.length >= 48) {announce("Достигнут предел в 48 блоков.",true);return;}
    let suffix = 1, id = type;
    while (nodeById(id)) id = `${type}-${++suffix}`;
    commitPositions();
    const node = {id,type,params:defaults(type)};
    const edge = fixed && edgeFrom(origin,node);
    const upstream = origin?.side === "input";
    const size = bounds(node,0,0);
    let x, y;
    if (position) {
      x = position.x - width(node) / 2;
      y = position.y - height(node) / 2;
      autoFit = false;
    } else if (fixed) {
      x = upstream ? bounds(fixed).left - COLUMN_GAP - size.right : bounds(fixed).right + COLUMN_GAP - size.left;
      y = fixed.y + portY(fixed,origin.port,upstream) - portY(node,upstream ? edge.port : edge.input,!upstream);
    } else {
      x = (scroller.clientWidth / 2 - left) / scale - width(node) / 2;
      y = (scroller.clientHeight / 2 - top) / scale - height(node) / 2;
    }
    if (!position) {
      const sameColumn = current.nodes.map(n => bounds(n)).filter(r => x+size.left < r.right+COLUMN_GAP && r.left < x+size.right+COLUMN_GAP);
      for (const r of sameColumn.sort((a,b) => a.top-b.top)) {
        if (y+size.top < r.bottom+ROW_GAP && r.top < y+size.bottom+ROW_GAP) y = r.bottom+ROW_GAP-size.top;
      }
    }
    node.x = clamp(Math.round(x),-100000,100000);
    node.y = clamp(Math.round(y),-100000,100000);
    current.nodes.push(node);
    if (edge) addEdge(edge.from.id,edge.to.id,edge.port,edge.input);
    selected = id; onChange(); draw();
    if (!position) {ensureVisible(node); inspectNode(node);}
    focusNode(id);
    announce(edge ? "Шаг добавлен и соединён." : "Шаг добавлен.");
  }
  function moveNode(n,x,y) {
    commitPositions();
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
    } else if (k === "caseSensitive") {
      n.params[k] = el.checked;
    } else if (["repository","language","manifest","directory","model","connection","suffix"].includes(k)) {
      if (v.trim()) n.params[k] = v.trim();
      else delete n.params[k];
    }
    else n.params[k] = k==="monthDay" || k === "value" && n.params.field === "count" && v !== "" ? Number(v) : v;
    onChange();
    if (["schedule","notify","model_load"].includes(n.type)) refreshSubtitle(n);
    if (k === "channel") {
      for (const hint of panel.querySelectorAll("[data-notice-channel]")) hint.hidden=hint.dataset.noticeChannel!==v;
      if (Object.hasOwn(recipientHints,v)) el.setAttribute("aria-describedby","studio-"+v+"-recipient");
      else el.removeAttribute("aria-describedby");
    }
    if (k === "repository") inspect();
    if (k === "name") draw();
  }
  section.addEventListener("click", event => {
    if (suppressClick && event.detail > 0 && scroller.contains(event.target)) {suppressClick = false; return;}
    const button = event.target.closest("button"), edge = event.target.closest("[data-inspect-edge]");
    if (edge) {clearWire(); inspectPacket(Number(edge.dataset.inspectEdge)); onInspect(); return;}
    if (button?.hasAttribute("data-studio-fit")) {fit();return;}
    if (button?.hasAttribute("data-zoom")) {zoom(Number(button.dataset.zoom) < 0 ? 1 / 1.25 : 1.25);return;}
    if (button?.hasAttribute("data-add-after") && canWrite()) {
      suggest({id:button.dataset.addAfter,port:button.dataset.afterPort,side:"output"},button); return;
    }
    if (button?.matches(SOCKET) && canWrite()) {
      const socket = socketRef(button);
      if (wire && socket.side !== wire.side) connectWire(button);
      else {
        startWire(button);
        announce(`Выберите ${socket.side === "input" ? "выход" : "вход"}. Клавиша «+» открывает каталог, Escape отменяет связь.`);
      }
      return;
    }
    if (button?.hasAttribute("data-studio-node")) {
      if (wire && canWrite()) connectWire(button);
      else select(button.dataset.studioNode,true);
      return;
    }
    if (scroller.contains(event.target)) clearWire();
    if (button?.hasAttribute("data-download-node")) {exportDefinition(nodeById(selected).params);return;}
    if (!canWrite()) return;
    if (button?.hasAttribute("data-model-settings")) {
      const current = graph(), n = nodeById(selected);
      if (n?.type !== "model_load" || !manageModels) return;
      onManageModels?.(n.params.connection || "",name => {
        if (!canWrite() || graph() !== current || !current.nodes.includes(n)) return;
        if (name && !modelConnections.includes(name)) modelConnections.push(name);
        if ((n.params.connection || "") !== name) {
          if (name) n.params.connection = name;
          else delete n.params.connection;
          onChange();
          refreshSubtitle(n);
        }
        if (selected === n.id) inspect();
      });
      return;
    }
    if (button?.matches("[data-new-step],[data-drop-step]")) {
      changeStep(nodeById(selected).params,button);onChange();draw();return;
    }
    if (button?.matches("[data-add-value],[data-remove-value]")) {
      const n = nodeById(selected);
      if (!["regex","custom"].includes(n?.type)) return;
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
    if (canWrite()) {
      const n=nodeById(selected);
      if (el.matches("[data-period]")) {
        delete n.params.monthDay;delete n.params.weekdays;
        if (el.value === "cron") {
          n.params.cron = "0 14 * * *";
          delete n.params.time;
        } else {
          if (Object.hasOwn(n.params,"cron")) n.params.time = "14:00";
          delete n.params.cron;
        }
        if (el.value==="weekly") n.params.weekdays=[1,2,3,4,5];
        if (el.value==="monthly") n.params.monthDay=1;
        onChange();inspect();return;
      }
      if (el.matches("[data-weekday]")) {
        const days=[...panel.querySelectorAll("[data-weekday]:checked")].map(box=>Number(box.dataset.weekday));
        if (!days.length) {el.checked=true; announce("Оставьте хотя бы один день недели.",true);return;}
        n.params.weekdays=days;onChange();return;
      }
      if (el.matches("[data-import-node]")) {
        const firstGraph=graph();
        importDefinition(el.files[0]).then(definition=>{
          if (!canWrite() || graph()!==firstGraph || !graph().nodes.includes(n)) return;
          Object.assign(n.params,definition);onChange();draw();announce("Определение загружено.");
        }).catch(error=>announce(error.message,true));return;
      }
      if (el.matches("[data-step-op],[data-step-text]")) {
        changeStep(n.params,el);onChange();if(el.matches("[data-step-op]")) inspect();return;
      }
    }
    if (el.matches(".studio-edge-form [name=port]")) refreshTargets();
    if (el.matches("[data-param]")) setParameter(el);
    if (el.matches("[data-value-index]") && canWrite()) {
      nodeById(selected).params.values[Number(el.dataset.valueIndex)] = el.value;
      onChange();
    }
  });
  scroller.addEventListener("keydown", event => {
    if (event.key === "Escape" && wire) {
      const origin = plane.querySelector(".canvas-origin");
      clearWire(); origin?.focus({preventScroll:true}); event.stopPropagation(); return;
    }
    const edge = event.target.closest("[data-inspect-edge]");
    if (edge && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault(); inspectPacket(Number(edge.dataset.inspectEdge)); onInspect(); return;
    }
    const key = event.key;
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    const socket = event.target.closest(SOCKET);
    if (key === "+" && socket && canWrite()) {
      event.preventDefault(); suggest(socketRef(socket),socket); return;
    }
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
    moveNode(n,placed(n).x + delta[0] * step,placed(n).y + delta[1] * step);
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
    const target = event.target, port = target.closest(SOCKET), body = target.closest("[data-studio-node]");
    const pan = event.button === 1 || event.ctrlKey || event.metaKey || !target.closest("button,[data-inspect-edge]");
    const details = {pointer:event.pointerId,x:event.clientX,y:event.clientY,moved:false};
    if (pan) {
      clearWire(); gesture = {...details,mode:"pan",left,top}; scroller.setPointerCapture(event.pointerId);
      scroller.classList.add("panning"); event.preventDefault();
    } else if (port && canWrite()) {
      gesture = {...details,mode:"wire",socket:port}; port.setPointerCapture(event.pointerId);
    } else if (body && canWrite() && !wire) {
      const node = nodeById(body.dataset.studioNode);
      gesture = {...details,mode:"node",node,originX:placed(node).x,originY:placed(node).y}; body.setPointerCapture(event.pointerId);
    }
  });
  scroller.addEventListener("pointermove", event => {
    const g = gesture;
    if (!g || g.pointer !== event.pointerId) return;
    const dx = event.clientX - g.x, dy = event.clientY - g.y;
    if (!g.moved && Math.hypot(dx,dy) < 4) return;
    if (!g.moved && g.mode === "wire") startWire(g.socket);
    g.moved = true;
    if (g.mode === "pan") {autoFit = false; left = g.left + dx; top = g.top + dy; applyView();}
    if (g.mode === "node" && canWrite()) {autoFit = false; moveNode(g.node,g.originX + dx / scale,g.originY + dy / scale);}
    if (g.mode === "wire" && wire) {
      const origin = placed(nodeById(wire.id)), end = world(event.clientX,event.clientY);
      const input = wire.side === "input";
      const x = origin.x + (input ? -9 : width(origin) + 5), y = origin.y + portY(origin,wire.port,input);
      plane.querySelector(".canvas-preview").setAttribute("d",input ? curve(end.x,end.y,x,y) : curve(x,y,end.x,end.y));
    }
  });
  function finishGesture(event) {
    if (!gesture || gesture.pointer !== event.pointerId) return;
    const {mode,moved,socket} = gesture; gesture = null; scroller.classList.remove("panning");
    if (mode === "node" && moved) onChange();
    if (moved) {suppressClick = true; setTimeout(() => {suppressClick = false;}, 0);}
    if (mode !== "wire") return;
    if (!moved) return;
    if (event.type !== "pointerup" || !wire) {clearWire();return;}
    const hit = document.elementFromPoint(event.clientX,event.clientY);
    const drop = hit?.closest(`${SOCKET},[data-studio-node]`);
    if (drop && plane.contains(drop)) connectWire(drop);
    else if (hit && scroller.contains(hit) && !hit.closest("[data-studio-box],[data-inspect-edge]")) {
      suggest(wire,socket,world(event.clientX,event.clientY));
    } else clearWire();
  }
  scroller.addEventListener("pointerup",finishGesture);
  scroller.addEventListener("pointercancel",finishGesture);
  scroller.addEventListener("lostpointercapture",finishGesture);
  section.addEventListener("dragstart", event => {
    const button = event.target.closest("[data-picker-type],[data-add-type]");
    if (button && canWrite()) event.dataTransfer.setData("application/x-studio-node",button.dataset.pickerType || button.dataset.addType);
  });
  scroller.addEventListener("dragover", event => {
    if (canWrite() && event.dataTransfer.types.includes("application/x-studio-node")) event.preventDefault();
  });
  scroller.addEventListener("drop", event => {
    const type = event.dataTransfer.getData("application/x-studio-node"); if (!type || !canWrite()) return;
    event.preventDefault();
    addNode(type,getAddOrigin(),world(event.clientX,event.clientY));
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
    const byId = new Map((stages || []).map(stage => [stage.id,stageStatus(getReport(), stage)]));
    for (const box of plane.querySelectorAll("[data-studio-box]")) {
      const status = byId.get(box.dataset.studioBox); box.querySelector(".studio-live")?.remove();
      if (!status) continue;
      const badge = document.createElement("span"); badge.className = "studio-live"; badge.dataset.status = status;
      badge.textContent = ({done:"Готово",partial:"Частично",running:"В работе",skipped:"Пропущен",error:"Ошибка"})[status] || status;
      box.append(badge);
    }
  }
  return {draw,fit,addNode,allowedTypes,statuses,dispose:() => observer.disconnect()};
}
