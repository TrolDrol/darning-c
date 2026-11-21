const WIN = "windows";
const LINUX = "linux";

function command(text) {
  return `<div class="model-command"><pre><code>${text}</code></pre><button class="model-copy" type="button" data-copy-command>Копировать</button></div>`;
}

function platform(os, content) {
  return `<div class="model-os" data-os="${os}" hidden>${content}</div>`;
}

export function installGuide() {
  return `<div class="model-guide">
    <h3>Подготовить сервер модели</h3>
    <p>Подойдёт Ubuntu x86_64. Для небольшой модели Qwen2.5 на CPU нужно от 4 ГБ оперативной памяти. Для GPU оставьте 15 ГБ на диске.</p>
    <p>Если у модели есть внешний HTTPS-порт, запишите его номер и соответствующий внутренний порт. Если доступен только SSH, «Штопка» может обращаться к модели через SSH со своего веб-сервера.</p>
    <section class="model-step"><h4>Скачайте мастер на свой компьютер</h4>
      <a class="button" href="/model-setup.py" download>Скачать model-setup.py</a>
      <label class="field model-platform">Операционная система вашего компьютера
        <select name="guideOS"><option value="windows">Windows · PowerShell</option><option value="linux">Ubuntu / Debian · терминал</option></select></label>
      <details class="model-help"><summary>Установить Python и клиент OpenSSH</summary>
        ${platform(WIN,`<p>Проверьте обе команды. Если одна из них отсутствует, установите соответствующий компонент.</p>
          ${command("python --version\nssh -V")}
          <p>Python 3.12</p>${command("winget install --exact --id Python.Python.3.12")}
          <p>Клиент OpenSSH · PowerShell от имени администратора</p>${command("Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0")}
          <p>После установки откройте новое окно PowerShell. <a href="https://docs.python.org/3/using/windows.html" target="_blank" rel="noopener">Python для Windows</a> · <a href="https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse" target="_blank" rel="noopener">OpenSSH от Microsoft</a></p>`)}
        ${platform(LINUX,`<p>На компьютере, откуда будете подключаться, нужны Python 3.9 или новее и клиент OpenSSH.</p>
          ${command("sudo apt update\nsudo apt install python3 openssh-client")}
          <p><a href="https://ubuntu.com/server/docs/how-to/security/openssh-server/" target="_blank" rel="noopener">OpenSSH в Ubuntu</a></p>`)}
      </details>
    </section>
    <section class="model-step"><h4>Запустите установку через SSH</h4>
      <p>Откройте терминал в папке со скачанным файлом. Мастер спросит адрес сервера и порты, подготовит модель и сохранит профиль подключения на вашем компьютере.</p>
      ${platform(WIN,command("python .\\model-setup.py"))}
      ${platform(LINUX,command("python3 ./model-setup.py"))}
      <details class="model-help"><summary>У провайдера открыт только SSH</summary>
        <div class="model-alternate"><p>В мастере выберите «2 — доступен только SSH». Если модель уже установлена и у вас есть JSON, используйте его.</p>
          <p>Для настройки маршрута оператору «Штопки» понадобятся проект, адрес и порт SSH, внутренний порт модели, а также поля <code>endpoint</code> и <code>fingerprint</code> из JSON. API-ключ указывается при импорте в студии.</p>
          <p>После подключения сервер «Штопки» сам открывает SSH-соединение при запросе. Ваш компьютер можно выключить.</p></div>
      </details>
      <details class="model-help"><summary>Скопировать мастер на сервер и запустить там</summary>
        <div class="model-alternate"><p>Подставьте свой адрес SSH и порт вместо <code>server.example</code> и <code>22</code>. На сервере нужен Python 3.9 или новее.</p>
          <p>На своём компьютере</p>${command("scp -P 22 model-setup.py root@server.example:model-setup.py\nssh -p 22 root@server.example")}
          <p>Если в образе Ubuntu 22.04 или новее ещё нет Python, установите его в открытом SSH-сеансе под root.</p>
          ${command("apt-get update\napt-get install -y python3")}
          <p>На сервере</p>${command("python3 model-setup.py --on-server")}
          <p>Откройте второй терминал на своём компьютере. Замените путь после двоеточия полным путём к профилю, который напечатает мастер.</p>
          ${command("scp -P 22 root@server.example:/root/.darning/model-ИМЯ.json .")}</div>
      </details>
    </section>
    <section class="model-step"><h4>Подключите модель к проекту</h4>
      <p>Выберите JSON-профиль из папки <code>.darning</code>. Мастер записал в него адрес модели, отпечаток сертификата и ключ доступа.</p>
      <label class="field">Импортировать подключение<input type="file" accept=".json,application/json" name="profileFile"></label>
    </section>
    <span class="model-copy-feedback" role="status" aria-live="polite"></span>
  </div>`;
}

export function bindGuide(form) {
  const os=form.elements.guideOS;
  os.value=/win/i.test(navigator.userAgentData?.platform || navigator.platform || "")?WIN:LINUX;
  function showPlatform() {
    for(const el of form.querySelectorAll("[data-os]")) el.hidden=el.dataset.os!==os.value;
  }
  showPlatform();
  os.addEventListener("change",showPlatform);
  form.addEventListener("click",async event=>{
    const button=event.target.closest("[data-copy-command]");
    if(!button) return;
    const code=button.parentElement.querySelector("code");
    const status=form.querySelector(".model-copy-feedback");
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent="Скопировано";
      status.textContent="Команда скопирована.";
      window.setTimeout(()=>{button.textContent="Копировать";},2000);
    } catch {
      const range=document.createRange();
      range.selectNodeContents(code);
      const selection=window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent="Текст команды выделен. Скопируйте его сочетанием клавиш или через меню браузера.";
    }
  });
}
