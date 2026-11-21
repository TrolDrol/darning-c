#!/usr/bin/env python3
"""Install or remove the Darning model service on its owner's Ubuntu server."""
import argparse
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


BASE = Path("/opt/darning-project-model")
NAME = "darning-project-model"
LABEL = "darning.model-worker"
USER = "darning-llm"
MODEL = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
WEIGHTS = ("https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/"
           "91cad51170dc346986eccefdc2dd33a9da36ead9/" + MODEL,
           "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e")
RELEASE = "https://github.com/ggml-org/llama.cpp/releases/download/b12569/"
ASSETS = {
    "cpu": (RELEASE + "llama-b12569-bin-ubuntu-x64.tar.gz",
            "6a2692d186dec59b9f9b1d500782ab496a1144404c0ae559fdea5d6495c744b1"),
    "cuda": (RELEASE + "llama-b12569-bin-ubuntu-cuda-12.8-x64.tar.gz",
             "d3de4cf00379312377db023811bf34d1dbdaee30919d41bdb7189d14ca321128"),
    "cudart": (RELEASE + "cudart-llama-b12569-bin-ubuntu-cuda-12.8-x64.tar.gz",
               "2039c97ffe0f0736331a7ffb8bf4f99ec8eca1c438bed54e48cd9e90b075a770"),
    "abi": ("https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-amd64.tar.gz",
            "e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86"),
}
IMAGES = {
    "cpu": "ghcr.io/ggml-org/llama.cpp@sha256:9f11c1a27d5bdadef2ebf8c629706bf0ed48173f0fea1a78c4dd666918134a8e",
    "cuda": "ghcr.io/ggml-org/llama.cpp@sha256:6b1c681b535a15d406c7270fd2730f5bd36d3598fbb0ca894bfa47857a700fe3",
}


def log(message):
    print(message, file=sys.stderr, flush=True)


def call(args, **kwargs):
    return subprocess.run(args, check=True, stdout=sys.stderr, **kwargs)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def download(path, source):
    url, expected = source
    if path.is_file() and digest(path) == expected:
        return
    partial = path.with_suffix(".part")
    log("Загрузка с проверкой SHA-256: " + path.name)
    for attempt in range(2):
        if not partial.is_file() or digest(partial) != expected:
            cmd = ["curl", "--fail", "--location", "--silent", "--show-error",
                   "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "20",
                   "--speed-limit", "1024", "--speed-time", "90", "--retry", "3",
                   "--continue-at", "-", "--output", partial, url]
            status = subprocess.run(cmd, stdout=sys.stderr).returncode
            if status and (attempt or status not in (33, 36)):
                raise ValueError("Ошибка загрузки " + path.name + ". Повторите запуск мастера.")
        if partial.is_file() and digest(partial) == expected:
            partial.replace(path)
            return
        partial.unlink(missing_ok=True)
    raise ValueError("SHA-256 файла " + path.name + " не совпал с закреплённым значением.")


def packages(names):
    if names:
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        call(["apt-get", "-q", "update"], env=env)
        call(["apt-get", "install", "-y", "--no-install-recommends", *names], env=env)


def owned_dir(path):
    s = path.lstat()
    return stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022


@contextlib.contextmanager
def installation(remove):
    import fcntl
    if not owned_dir(BASE.parent):
        raise ValueError("Для установки требуется каталог /opt, принадлежащий root.")
    # Lock the stable parent across first creation and final removal of the worker directory.
    lock = os.open(BASE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Установка уже выполняется. Повторите позднее.") from None
        marker = BASE / ".managed-v1"
        if BASE.exists() or BASE.is_symlink():
            if not owned_dir(BASE) or not marker.is_file() or marker.is_symlink() or marker.stat().st_uid:
                raise ValueError("Каталог /opt/darning-project-model занят другой установкой.")
        elif remove:
            yield False
            return
        else:
            BASE.mkdir(mode=0o700)
            marker.touch(mode=0o600)
        # Older standalone installers synchronize on this file.
        with (BASE / ".install-lock").open("a") as legacy_lock:
            try:
                fcntl.flock(legacy_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Установка уже выполняется. Повторите позднее.") from None
            yield True
    finally:
        os.close(lock)


def service_account(create):
    import pwd
    record = BASE / ".native-user"
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        if not create:
            return None
        # Written first so an interrupted useradd can be retried.
        record.touch(mode=0o600)
        call(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
              "--shell", "/usr/sbin/nologin", "--comment", NAME, USER])
        account = pwd.getpwnam(USER)
    if not record.is_file() or account.pw_gecos != NAME or account.pw_shell != "/usr/sbin/nologin":
        raise ValueError("Системное имя " + USER + " занято другой службой.")
    identity = f"{account.pw_uid}:{account.pw_gid}"
    previous = record.read_text().strip()
    if previous and previous != identity:
        raise ValueError("Учётная запись модели изменилась. Проверьте её вручную.")
    if not previous:
        record.write_text(identity)
    return account


def runtime(kind):
    """Materialize only ordinary runtime files and local SONAME links from pinned archives."""
    dest = BASE / ("runtime-" + kind)
    if (dest / ".files").is_file():
        return dest
    archive = BASE / (kind + ".tar.gz")
    download(archive, ASSETS[kind])
    stage = BASE / ("stage-" + kind)
    stage.mkdir(mode=0o755, exist_ok=True)
    if not owned_dir(stage):
        raise ValueError("Некорректный промежуточный каталог модели: " + str(stage))
    stage.chmod(0o755)
    names = []
    with tarfile.open(archive) as tar:
        for member in tar:
            directory, _, name = member.name.rpartition("/")
            if kind == "abi":
                if directory != "usr/lib/x86_64-linux-gnu" or not re.fullmatch(
                    r"ld-linux-x86-64\.so\.2|lib(c|m|pthread|dl|rt)\.so\.[0-9]+|"
                    r"libstdc\+\+\.so\.6(?:\.0\.\d+)?|libgcc_s\.so\.1|lib(ssl|crypto)\.so\.3", name
                ):
                    continue
            elif "/" in directory or not re.fullmatch(r"llama-server|lib[a-zA-Z0-9+_.-]+\.so(?:\.[0-9.]+)?", name):
                continue
            target = stage / name
            if member.issym() and re.fullmatch(r"lib[a-zA-Z0-9+_.-]+", member.linkname):
                target.unlink(missing_ok=True)
                target.symlink_to(member.linkname)
            elif member.isfile():
                target.unlink(missing_ok=True)
                with tar.extractfile(member) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out)
                target.chmod(0o755)
            else:
                continue
            names.append(name)
    required = {"cpu": "llama-server", "cuda": "libggml-cuda.so", "cudart": "libcudart.so.12",
                "abi": "ld-linux-x86-64.so.2"}[kind]
    if not (stage / required).is_file():
        raise ValueError("В архиве отсутствует " + required)
    (stage / ".files").write_text("\n".join(names))
    stage.rename(dest)
    archive.unlink()
    return dest


def state_write(data):
    tmp = BASE / ".state.new"
    tmp.write_text(json.dumps(data))
    tmp.replace(BASE / ".state")


def proc_identity(pid):
    try:
        fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return fields[19] if fields[0] != "Z" else None
    except FileNotFoundError:
        return None


def native_alive(state):
    if not state.get("birth") or proc_identity(state["pid"]) != state["birth"]:
        return False
    if state.get("boot") and state["boot"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        return False
    pid_dir = Path("/proc") / str(state["pid"])
    try:
        uid = (BASE / ".native-user").read_text().split(":", 1)[0]
        status = (pid_dir / "status").read_text().splitlines()
        argv = (pid_dir / "cmdline").read_bytes().split(b"\0")
        return (next(line for line in status if line.startswith("Uid:")).split()[1] == uid
                and os.fsencode(BASE / MODEL) in argv and b"darning-qwen" in argv)
    except FileNotFoundError:
        return False


def stop_native(state):
    pid = state.get("pid")
    if not pid:
        return
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        if not native_alive(state):
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            signal.pidfd_send_signal(fd, sig)
            for _ in range(50):
                if proc_identity(pid) is None:
                    return
                time.sleep(0.1)
        raise ValueError("Не удалось остановить процесс модели.")
    finally:
        os.close(fd)


def identity(gid):
    key, crt, private = (BASE / n for n in ("api_key", "tls.crt", "tls.key"))
    if not key.exists():
        tmp = BASE / "api_key.new"
        tmp.write_text(secrets.token_hex(32) + "\n")
        tmp.replace(key)
    if not re.fullmatch(r"[a-f0-9]{64}", key.read_text().strip()):
        raise ValueError("Повреждён ключ API установленной модели.")
    pending_crt = BASE / "tls.crt.new"
    if private.exists() and not crt.exists() and pending_crt.is_file():
        public_from_key = subprocess.check_output(["openssl", "pkey", "-in", private, "-pubout"])
        public_from_cert = subprocess.check_output(["openssl", "x509", "-in", pending_crt, "-pubkey", "-noout"])
        if public_from_key == public_from_cert:
            pending_crt.replace(crt)
    if crt.exists() != private.exists():
        raise ValueError("В каталоге установки неполная пара сертификата и ключа TLS.")
    if not crt.exists():
        call(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "825",
              "-subj", "/CN=darning-project-model", "-keyout", BASE / "tls.key.new", "-out", BASE / "tls.crt.new"],
             stderr=subprocess.DEVNULL)
        (BASE / "tls.key.new").replace(private)
        (BASE / "tls.crt.new").replace(crt)
    for path in (key, private):
        os.chown(path, 0, gid)
        path.chmod(0o640)
    crt.chmod(0o644)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(crt.read_text())).hexdigest()


def model_args(port, bind, cuda, docker=False):
    locations = ("/model.gguf", "/key", "/tls.crt", "/tls.key") if docker else (
        str(BASE / MODEL), str(BASE / "api_key"), str(BASE / "tls.crt"), str(BASE / "tls.key"))
    model, key, crt, private = locations
    args = ["--model", model, "--alias", "darning-qwen", "--host", bind, "--port", str(port),
            "-c", "4096", "-np", "1", "-ngl", "99" if cuda else "0", "--api-key-file", key,
            "--ssl-cert-file", crt, "--ssl-key-file", private, "--no-webui"]
    return args + (["--device", "CUDA0"] if cuda and not docker else [])


def native_start(account, port, bind, cuda):
    kind = "cuda" if cuda else "cpu"
    folder = runtime(kind)
    binary = str(folder / "llama-server")
    prefix = []
    env = {"HOME": "/nonexistent", "PATH": "/usr/bin:/bin"}
    if cuda:
        libraries = [str(folder)]
        # The CUDA release targets Ubuntu 24.04. An older host keeps its system libc.
        if tuple(map(int, platform.libc_ver()[1].split(".")[:2])) < (2, 39):
            abi = runtime("abi")
            prefix = [str(abi / "ld-linux-x86-64.so.2")]
            libraries.append(str(abi))
        libraries.extend(["/usr/local/nvidia/lib64", "/usr/local/cuda/lib64"])
        # CUDA runtime and cuBLAS must match the exact release used by the backend.
        libraries.insert(1, str(runtime("cudart")))
        if prefix:
            prefix += ["--library-path", ":".join(libraries)]
        else:
            env["LD_LIBRARY_PATH"] = ":".join(libraries)
    # CUDA devices can be restricted to the video/render group by the provider.
    groups = sorted({p.stat().st_gid for p in Path("/dev").glob("nvidia*")
                     if p.is_char_device() and p.stat().st_gid}) if cuda else []
    drop = ["setpriv", "--no-new-privs", "--reuid", str(account.pw_uid), "--regid", str(account.pw_gid)]
    drop += ["--groups", ",".join(map(str, groups))] if groups else ["--clear-groups"]
    command = drop + prefix + [binary]
    if cuda:
        devices = subprocess.run(command + ["--list-devices"], cwd=folder, env=env, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        if devices.returncode or "CUDA0:" not in devices.stdout:
            raise ValueError("CUDA0 недоступно для процесса модели. " + devices.stdout[-1000:].strip())
    logfile = BASE / "server.log"
    with logfile.open("wb") as out:
        process = subprocess.Popen(command + model_args(port, bind, cuda), cwd=folder, env=env,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
    state = {"mode": "native", "device": kind, "port": port, "bind": bind,
             "pid": process.pid, "birth": proc_identity(process.pid),
             "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    state_write(state)
    return state


def gpu_available():
    if not shutil.which("nvidia-smi"):
        return False
    result = subprocess.run(["nvidia-smi", "-L"], capture_output=True, text=True, timeout=30)
    return result.returncode == 0 and result.stdout.startswith("GPU ")


def container():
    found = subprocess.check_output(["docker", "ps", "-aq", "--filter", f"name=^/{NAME}$"], text=True).strip()
    if not found:
        return None
    info = json.loads(subprocess.check_output(["docker", "inspect", "--type=container", found]))[0]
    if (info["Config"].get("Labels") or {}).get(LABEL) != "1":
        raise ValueError("Имя контейнера " + NAME + " занято другой службой.")
    return info


def docker_start(port, bind):
    info = container()
    if info:
        ports = info["HostConfig"]["PortBindings"].get("8443/tcp") or []
        if not any(p["HostPort"] == str(port) and (p["HostIp"] or "0.0.0.0") == bind for p in ports):
            raise ValueError("Установленный контейнер использует другой адрес или внутренний порт. "
                             "Повторите запуск с прежними параметрами.")
        call(["docker", "start", info["Id"]])
        cuda = bool(info["HostConfig"].get("DeviceRequests"))
    else:
        cuda = gpu_available() and "nvidia" in json.loads(subprocess.check_output(
            ["docker", "info", "--format", "{{json .Runtimes}}"]))
        args = ["docker", "run", "-d", "--name", NAME, "--label", LABEL + "=1", "--restart", "unless-stopped",
                "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--user", "65534:65534",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--log-opt", "max-size=10m",
                "--log-opt", "max-file=2", "-e", "HOME=/tmp", "-p", f"{bind}:{port}:8443"]
        if cuda:
            args += ["--gpus", "all"]
        for local, remote in ((MODEL, "/model.gguf"), ("api_key", "/key"), ("tls.crt", "/tls.crt"), ("tls.key", "/tls.key")):
            args += ["-v", f"{BASE / local}:{remote}:ro"]
        call(args + [IMAGES["cuda" if cuda else "cpu"]] + model_args(8443, "0.0.0.0", cuda, docker=True))
    state = {"mode": "docker", "device": "cuda" if cuda else "cpu", "port": port, "bind": bind}
    state_write(state)
    return state


def ready(state, pin):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    expires = time.monotonic() + 240
    while time.monotonic() < expires:
        if state["mode"] == "native" and (not state["birth"] or proc_identity(state["pid"]) != state["birth"]):
            raise ValueError("Процесс модели завершился. Журнал: " + str(BASE / "server.log"))
        conn = http.client.HTTPSConnection("127.0.0.1", state["port"], context=context, timeout=3)
        try:
            conn.connect()
            if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != pin:
                raise ValueError("На выбранном внутреннем порту находится другой HTTPS-сервис.")
            conn.request("GET", "/health")
            if conn.getresponse().status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        time.sleep(1)
    raise ValueError("Модель не ответила за 4 минуты. Проверьте память и журнал " +
                     (str(BASE / "server.log") if state["mode"] == "native" else "docker logs " + NAME))


def cleanup(state):
    if state.get("mode") == "docker" or (not state and (Path("/proc/1/comm").read_text().strip() == "systemd")
                                        and shutil.which("docker")):
        if not shutil.which("docker"):
            raise ValueError("Для удаления установленного контейнера нужен Docker.")
        info = container()
        if info:
            call(["docker", "rm", "-f", info["Id"]])
    elif state.get("mode") == "native":
        stop_native(state)
    if (BASE / ".native-user").exists():
        account = service_account(False)
        if account:
            # A rental PID 1 can leave a zombie after SIGTERM. Ignore only dead processes.
            for proc in Path("/proc").iterdir():
                if not proc.name.isdecimal():
                    continue
                try:
                    if proc.stat().st_uid == account.pw_uid and proc_identity(int(proc.name)):
                        raise ValueError("Другая активная задача использует системную учётную запись модели.")
                except FileNotFoundError:
                    continue
            call(["userdel", "--force", USER])
    files = {MODEL, MODEL.rsplit(".", 1)[0] + ".part", "weights.part", "tls.crt", "tls.key", "api_key",
             "tls.crt.new", "tls.key.new", "api_key.new", "server.log", ".state", ".state.new",
             ".install-lock", ".native-user"}
    for kind in ASSETS:
        files.update([kind + ".tar.gz", kind + ".tar.part"])
        for prefix in ("runtime-", "stage-"):
            folder = BASE / (prefix + kind)
            if not folder.exists():
                continue
            if not owned_dir(folder):
                raise ValueError("В каталоге установки обнаружен посторонний путь: " + str(folder))
            inventory = folder / ".files"
            if inventory.exists():
                for name in inventory.read_text().splitlines():
                    if re.fullmatch(r"[a-zA-Z0-9+_.-]+", name) and name not in (".", ".."):
                        (folder / name).unlink(missing_ok=True)
                inventory.unlink()
            elif prefix == "stage-":
                # A verified extraction can have stopped before its inventory was committed.
                for item in folder.iterdir():
                    if item.is_file() and re.fullmatch(r"llama-server|lib[a-zA-Z0-9+_.-]+|ld-linux-x86-64\.so\.2", item.name):
                        item.unlink()
            if not any(folder.iterdir()):
                folder.rmdir()
    for name in files:
        (BASE / name).unlink(missing_ok=True)
    others = [p for p in BASE.iterdir() if p.name != ".managed-v1"]
    if others:
        os.chown(BASE, 0, 0)
        BASE.chmod(0o700)
        log("Сохранены дополнительные файлы владельца в " + str(BASE))
    else:
        (BASE / ".managed-v1").unlink()
        BASE.rmdir()


def worker(port, bind, action):
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if (os.geteuid() or platform.machine() != "x86_64" or release.get("ID", "").strip('"') != "ubuntu"
            or sys.version_info < (3, 8)):
        raise ValueError("Требуется Ubuntu x86_64, Python 3.8+ и права root или sudo.")
    systemd = Path("/proc/1/comm").read_text().strip() == "systemd" and Path("/run/systemd/system").is_dir()
    if not systemd and (int(release.get("VERSION_ID", "0").strip('"').split(".")[0]) < 22 or sys.version_info < (3, 9)):
        raise ValueError("Для нативной установки требуется Ubuntu 22.04 или новее и Python 3.9+.")
    os.umask(0o077)
    with installation(action == "remove") as present:
        if not present:
            return
        state_file = BASE / ".state"
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        if action == "remove":
            cleanup(state)
            return
        if action == "tunnel" and state:
            port, bind = state["port"], state["bind"]
            log(f"Используем прежний адрес службы на Ubuntu — {bind}:{port}.")
        docker = state.get("mode", "docker" if systemd else "native") == "docker"
        log("Режим установки: " + ("Docker с systemd." if docker else "нативный процесс, без systemd и Docker."))
        if not docker and not native_alive(state):
            with socket.socket() as test_port:
                test_port.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    test_port.bind((bind, port))
                except OSError as err:
                    raise ValueError(f"Порт {bind}:{port} недоступен. "
                                     "Выберите свободный --listen-port и настройте его у провайдера.") from err
        needs = [pkg for binary, pkg in (("curl", "curl"), ("openssl", "openssl")) if not shutil.which(binary)]
        if not Path("/etc/ssl/certs/ca-certificates.crt").is_file():
            needs.append("ca-certificates")
        if docker and not shutil.which("docker"):
            needs.append("docker.io")
        if not docker:
            for package, fname in (("libgomp1", "libgomp.so.1"), ("libstdc++6", "libstdc++.so.6")):
                if not (Path("/usr/lib/x86_64-linux-gnu") / fname).exists():
                    needs.append(package)
        packages(needs)
        if docker:
            call(["systemctl", "enable", "--now", "docker"])
            container()  # Catch name conflicts before creating any credentials.
            account = None
        else:
            account = service_account(True)
            os.chown(BASE, 0, account.pw_gid)
            BASE.chmod(0o750)
        pin = identity(65534 if docker else account.pw_gid)
        download(BASE / MODEL, WEIGHTS)
        (BASE / MODEL).chmod(0o644)
        if docker:
            state = docker_start(port, bind)
            ready(state, pin)
        elif native_alive(state):
            if (port, bind) != (state["port"], state["bind"]):
                raise ValueError("Процесс уже работает с другими параметрами. "
                                 "Используйте прежние --listen-port и --bind-loopback.")
            ready(state, pin)
        else:
            if gpu_available():
                try:
                    state = native_start(account, port, bind, True)
                    ready(state, pin)
                except (ValueError, subprocess.TimeoutExpired) as exc:
                    if state.get("mode") == "native":
                        stop_native(state)
                    log("CUDA недоступна. " + str(exc) + "\nЗапуск на CPU.")
                    state = {}
            else:
                log("NVIDIA не обнаружена. Запуск на CPU.")
                state = {}
            if not state:
                state = native_start(account, port, bind, False)
                try:
                    ready(state, pin)
                except BaseException:
                    stop_native(state)
                    raise
        log(f"Вычисления на {state['device'].upper()}.")
        if state["mode"] == "native":
            log("Можно закрыть SSH. После перезапуска арендованного контейнера повторите команду мастера.")
        print(pin)
        print((BASE / "api_key").read_text().strip())
        if action == "tunnel":
            print(state["port"])


def valid_host(value):
    value = (value or "").strip()
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        if len(value) <= 253 and re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
            return value.lower()
        raise ValueError("Укажите IPv4-адрес или DNS-имя без имени пользователя и порта.") from None


def ask(value, prompt, default=None):
    if value is not None:
        return value
    if default is None or sys.stdin.isatty():
        answer = input(prompt + (f" [{default}]" if default is not None else "") + ": ").strip()
        if answer:
            return answer
    return default


def valid_port(value, minimum=1):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Укажите порт от {minimum} до 65535.") from None
    if not minimum <= value <= 65535:
        raise ValueError(f"Укажите порт от {minimum} до 65535.")
    return value


def connection_settings(args, ssh_host):
    route = "local" if args.bind_loopback else "direct"
    choose_route = sys.stdin.isatty() and not args.bind_loopback and args.public_port is None
    if choose_route:
        log("Как сервер сайта «Штопка» будет подключаться к модели?\n"
            "  1 — провайдер выделил отдельный внешний TCP-порт для HTTPS модели.\n"
            "  2 — доступен только SSH. Нужен туннель от сервера сайта, который настраивает оператор «Штопки».")
        while True:
            choice = input("Введите 1 или 2: ").strip()
            if choice in ("1", "2"):
                break
            log("Посмотрите список портов в панели аренды. Если указан только SSH, введите 2.")
        route = "direct" if choice == "1" else "operator"
    inside = valid_port(ask(args.listen_port, "Порт модели внутри Ubuntu", 18443), 1024)
    if route == "operator":
        host = valid_host(ask(args.public_host, "Имя или IPv4 сервера аренды для профиля модели", ssh_host))
        return route, inside, host, inside
    if route == "local":
        log("Для --bind-loopback укажите адрес, по которому сервер приложения видит готовый SSH-туннель. "
            "Туннель на вашем ноутбуке доступен локальной «Штопке».")
        host = valid_host(ask(args.public_host, "Адрес туннеля со стороны приложения", "127.0.0.1"))
        outside = valid_port(ask(args.public_port, "Порт HTTPS на стороне туннеля", inside))
    else:
        log(f"В панели аренды найдите внешний TCP-порт, направленный на порт {inside} внутри Ubuntu.")
        host = valid_host(ask(args.public_host, "Адрес HTTPS модели, доступный сайту", ssh_host))
        port = ask(args.public_port, "Внешний TCP-порт HTTPS из панели аренды", None if choose_route else inside)
        outside = valid_port(port)
    return route, inside, host, outside


def main():
    parser = argparse.ArgumentParser(description="Установить модель Штопки на свой сервер")
    parser.add_argument("--on-server", action="store_true", help="Запустить скачанный мастер прямо на Ubuntu")
    parser.add_argument("--uninstall", action="store_true", help="Удалить установленную мастером модель и ключи")
    parser.add_argument("--host", help="SSH-адрес")
    parser.add_argument("--port", type=int, help="Порт SSH")
    parser.add_argument("--user", help="Пользователь SSH с правами root или sudo без пароля")
    parser.add_argument("--identity", help="Файл ключа OpenSSH на этом компьютере")
    parser.add_argument("--known-hosts", help="Файл проверенных ключей хостов OpenSSH")
    parser.add_argument("--profile-dir", type=Path, help="Личный каталог для нового JSON-профиля (по умолчанию ~/.darning)")
    parser.add_argument("--public-host", help="Имя или IPv4, по которому сайт подключается к модели")
    parser.add_argument("--public-port", type=int, help="Внешний порт HTTPS модели")
    parser.add_argument("--listen-port", type=int, help="Внутренний порт модели на Ubuntu (по умолчанию 18443)")
    parser.add_argument("--bind-loopback", action="store_true", help="Слушать только 127.0.0.1 для отдельного туннеля")
    args = parser.parse_args()
    if sys.version_info < (3, 9):
        raise ValueError("Мастеру требуется Python 3.9 или новее.")
    if not args.uninstall and sys.stdin.isatty():
        log("Если модель уже работает и JSON сохранён, используйте существующий профиль. "
            "При доступе только по SSH оператор «Штопки» может настроить к нему туннель без повторной установки.")
    ssh_host, ssh_port = None, None
    if args.on_server:
        if not hasattr(os, "geteuid"):
            raise ValueError("--on-server предназначен для Ubuntu.")
        command = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + [sys.executable, "-"]
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise ValueError("Установите клиент OpenSSH на этот компьютер.")
        ssh_host = valid_host(ask(args.host, "Адрес сервера SSH"))
        user = ask(args.user, "Пользователь SSH", "root")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise ValueError("Проверьте имя пользователя SSH.")
        ssh_port = valid_port(ask(args.port, "Порт SSH", 22))
        command = [ssh, "-T", "-o", "StrictHostKeyChecking=ask", "-o", "ForwardAgent=no",
                   "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", "-p", str(ssh_port)]
        if args.known_hosts:
            command += ["-o", "UserKnownHostsFile=" + str(Path(args.known_hosts).resolve())]
        keyfile = ask(args.identity, "Файл ключа SSH (Enter для стандартного ключа или пароля)", "")
        if keyfile:
            command += ["-i", str(Path(keyfile.strip('"')).expanduser())]
        command += [user + "@" + ssh_host, "python3 -" if user == "root" else "sudo -n python3 -"]
    inside, route = 18443, "direct"
    if not args.uninstall:
        log("Модель занимает 1,12 ГБ. Для CPU требуется от 4 ГБ памяти.")
        route, inside, host, outside = connection_settings(args, ssh_host)
        if route != "operator" and host == ssh_host and outside == ssh_port:
            raise ValueError("Адрес и порт модели совпадают с SSH. Укажите внешний TCP-порт HTTPS из панели аренды.")
    mode = "remove" if args.uninstall else "install"
    bind = "127.0.0.1" if args.bind_loopback else "0.0.0.0"
    if route == "operator":
        mode, bind = "tunnel", "127.0.0.1"
    remote_args = ["--worker", str(inside), bind, mode]
    if args.on_server:
        command.extend(remote_args)
    else:
        command[-1] += " " + " ".join(remote_args)
    result = subprocess.run(command, input=Path(__file__).read_bytes(), stdout=subprocess.PIPE)
    if result.returncode:
        raise ValueError(f"Код завершения {result.returncode}. Подробности выше. "
                         "После устранения причины повторите ту же команду.")
    if args.uninstall:
        print("Установленная мастером модель удалена. Сохранённый у вас JSON содержит прежний ключ.")
        return
    lines = result.stdout.decode("ascii").splitlines()
    if route == "operator":
        if len(lines) != 3 or not re.fullmatch(r"[0-9]{1,5}", lines[2]):
            raise ValueError("Сервер не подтвердил внутренний порт модели.")
        inside = outside = valid_port(lines.pop(), 1024)
    if len(lines) != 2 or not all(re.fullmatch(r"[0-9a-f]{64}", line) for line in lines):
        raise ValueError("Сервер не вернул подтверждение установки. Проверьте журнал выше.")
    directory = (args.profile_dir or Path.home() / ".darning").expanduser().resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix="model-", suffix=".json", dir=directory)
    origin = f"https://{host}:{outside}"
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"format": "darning-model-v1", "endpoint": origin + "/v1", "model": "darning-qwen",
                   "fingerprint": lines[0], "apiKey": lines[1]}, f, indent=2)
    print(f"Проверка на сервере модели прошла. HTTPS /health ответил на 127.0.0.1:{inside}.")
    print("Соединение с сервера сайта ещё не проверено.")
    if route == "operator":
        print(f"Оператору «Штопки» нужны проект, адрес профиля {origin}, отпечаток сертификата {lines[0]}, "
              f"адрес и порт SSH, имя пользователя и внутренний порт модели {inside}. "
              "Оператор настроит постоянный туннель от сайта и привяжет его к этому профилю. "
              "JSON с ключом API храните у себя.")
    elif route == "local":
        print(f"Проверьте, что сервер приложения видит туннель по адресу {origin}. "
              "Для размещённой «Штопки» туннель настраивает оператор сайта.")
    else:
        print(f"Если проверка с сайта не пройдёт, проверьте в панели аренды проброс внешнего TCP-порта {outside} "
              f"на внутренний {inside} и доступ с сервера «Штопки». Если доступен только SSH, "
              "оператор сайта может привязать туннель к существующему профилю. Переустановка модели не требуется.")
    print("Импортируйте JSON в настройки модели проекта и нажмите «Проверить подключение» для проверки с сайта.")
    if args.on_server:
        print("Скопируйте файл на свой компьютер через scp, используя SSH-адрес и порт аренды.")
    print("Файл подключения с API-ключом:", filename)


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--worker"]:
            _, _, raw_port, address, action = sys.argv
            if address not in ("0.0.0.0", "127.0.0.1") or action not in ("install", "tunnel", "remove"):
                raise ValueError("Недопустимые параметры службы.")
            worker(valid_port(raw_port, 1024), address, action)
        else:
            main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt, EOFError) as error:
        sys.exit("Установка не завершена. " + str(error))
