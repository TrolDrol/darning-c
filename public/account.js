import {telegramSettings} from "/telegram_settings.js";
import {emailSettings} from "/account_email.js";

async function avatarFromFile(file) {
  if (!["image/jpeg","image/png","image/webp"].includes(file.type) || file.size > 10 * 1024 * 1024) {
    throw Error("Выберите изображение JPG, PNG или WebP размером до 10 МБ.");
  }
  let image;
  try { image = await createImageBitmap(file); }
  catch { throw Error("Не удалось прочитать изображение."); }
  try {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 96;
    const side = Math.min(image.width,image.height);
    canvas.getContext("2d").drawImage(image,(image.width-side)/2,(image.height-side)/2,side,side,0,0,96,96);
    return canvas.toDataURL("image/png");
  } finally { image.close(); }
}

export function createAccountEditor({request,getViewer,getProject,onSave}) {
  const menu = document.querySelector(".account-tools");
  const trigger = menu.querySelector("summary");
  const dialog = document.querySelector("#profile-dialog");
  const form = dialog.querySelector("form");
  const file = form.elements.avatarFile;
  const submit = form.querySelector("[type=submit]");
  const preview = form.querySelector("[data-avatar-preview]");
  const remove = form.querySelector("[data-remove-avatar]");
  const cancel = form.querySelector("[data-profile-cancel]");
  const error = form.querySelector('[role="alert"]');
  let avatar, revision = 0, saving = false;
  const telegram = menu.querySelector("#account-telegram");
  menu.addEventListener("toggle", () => {
    if (menu.open) telegram.hidden = getViewer()?.role === "reader" || getProject()?.role !== "manager";
  });
  telegram.onclick = () => {
    const project = getProject();
    if (!project || project.role !== "manager") return;
    menu.open = false;
    telegramSettings({request,project:project.id,projectName:project.name});
  };
  menu.querySelector("#account-email").onclick = () => {
    menu.open = false;
    emailSettings(request);
  };
  function paint(img, src) {
    if (src && img.getAttribute("src") !== src) img.src = src;
    if (!src) img.removeAttribute("src");
    img.hidden = !src;
  }
  function showPreview(src) {
    paint(preview,src);
    remove.hidden = !src;
  }
  function refresh() {
    const user = getViewer();
    menu.querySelector("#account-admin").hidden = user?.role !== "super_admin";
    menu.querySelector("#account-display-name").textContent = user?.displayName || "";
    menu.querySelector("[data-avatar-default]").toggleAttribute("hidden",Boolean(user?.avatar));
    paint(menu.querySelector("[data-account-avatar]"),user?.avatar);
  }
  menu.querySelector("#edit-account").addEventListener("click", () => {
    const user = getViewer();
    if (!user) return;
    menu.open = false;
    form.reset();
    form.elements.displayName.value = user.displayName;
    avatar = undefined;
    showPreview(user.avatar);
    submit.disabled = false;
    error.textContent = "";
    dialog.showModal();
    form.elements.displayName.focus();
  });
  file.addEventListener("change", async () => {
    const image = file.files[0];
    if (!image) return;
    const token = ++revision;
    submit.disabled = true;
    error.textContent = "";
    try {
      const src = await avatarFromFile(image);
      if (token === revision) { avatar = src; showPreview(avatar); }
    } catch (err) {
      if (token === revision) { error.textContent = err.message; file.value = ""; }
    } finally { if (token === revision) submit.disabled = false; }
  });
  remove.onclick = () => { revision++; avatar = null; file.value = ""; showPreview(null); submit.disabled = false; };
  cancel.onclick = () => dialog.close();
  dialog.addEventListener("cancel", event => { if (saving) event.preventDefault(); });
  dialog.addEventListener("close", () => { revision++; if (getViewer()) trigger.focus(); });
  form.onsubmit = async event => {
    event.preventDefault();
    if (submit.disabled || saving) return;
    saving = true;
    submit.disabled = cancel.disabled = remove.disabled = file.disabled = form.elements.displayName.disabled = true;
    error.textContent = "";
    try {
      const payload = {displayName:form.elements.displayName.value.trim()};
      if (avatar !== undefined) payload.avatar = avatar;
      const result = await request("/api/account/profile", payload);
      if (getViewer()) { onSave(result.viewer); dialog.close(); }
    } catch (err) { error.textContent = err.message; }
    finally { saving = submit.disabled = cancel.disabled = remove.disabled = file.disabled = form.elements.displayName.disabled = false; }
  };
  return {refresh,reset() { menu.open = false; if (dialog.open) dialog.close(); refresh(); }};
}
