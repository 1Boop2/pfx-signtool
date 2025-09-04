#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Подпись приложений через signtool.exe с .pfx сертификатом.

Примеры:
  1) Подписать один файл:
     python sign_with_pfx.py --pfx C:\certs\mycert.pfx --pfx-pass-env SIGN_PASS ^
         --input dist\MyApp.exe --verify

  2) Подписать все исполняемые файлы в папке рекурсивно:
     python sign_with_pfx.py --pfx C:\certs\mycert.pfx --pfx-pass-env SIGN_PASS ^
         --input dist\ --recursive --verify

  3) Dual-sign (сначала SHA1 + /t, затем добавление SHA256 + /tr):
     python sign_with_pfx.py --pfx C:\certs\mycert.pfx --pfx-pass-env SIGN_PASS ^
         --input dist\ --recursive --dual --t http://timestamp.digicert.com ^
         --tr http://timestamp.digicert.com --verify

  4) Явно указать путь к signtool.exe:
     python sign_with_pfx.py --signtool "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" ^
         --pfx C:\certs\mycert.pfx --pfx-pass-env SIGN_PASS --input dist\MyApp.exe

Примечания по безопасности:
- Никогда не храните пароль PFX в коде/репозитории. Используйте переменные окружения (например SIGN_PASS).
- По умолчанию скрипт пропускает уже подписанные файлы. Если нужно заменить существующую подпись(и),
  используйте флаг --replace-existing (внимание: это может перезаписать подписи).
"""

from __future__ import annotations
import argparse
import concurrent.futures as cf
import glob
import logging
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess, run, PIPE
from typing import Iterable, List, Optional, Sequence, Tuple

DEFAULT_EXTS = (".exe", ".dll", ".sys", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle")

@dataclass
class Options:
    signtool: str
    pfx: str
    pfx_pass: str
    input_paths: List[Path]
    recursive: bool
    include_exts: Tuple[str, ...]
    verify: bool
    skip_signed: bool
    replace_existing: bool
    dual: bool
    tr_url: Optional[str]
    legacy_t_url: Optional[str]
    no_timestamp: bool
    description: Optional[str]
    description_url: Optional[str]
    workers: int
    what_if: bool
    arch: str  # 'x64' or 'x86'
    verbose_signtool: bool

@dataclass
class SignResult:
    file: Path
    ok: bool
    skipped: bool
    message: str

def die(msg: str, code: int = 2) -> None:
    logging.error(msg)
    sys.exit(code)

def is_windows() -> bool:
    return platform.system().lower().startswith("win")

def find_signtool(explicit: Optional[str], arch: str) -> str:
    """
    Находит signtool.exe:
    1) если задан явный путь — проверяет его,
    2) если есть в PATH — использует,
    3) ищет в стандартных каталогах Windows SDK и берёт самую новую версию.
    """
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        die(f"signtool не найден по указанному пути: {explicit}")

    st = shutil.which("signtool")
    if st:
        return st

    # Поиск в типичных каталогах Windows Kits
    candidates: List[str] = []
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    bases = [
        Path(pf86) / "Windows Kits" / "10" / "bin",
        Path(pf86) / "Windows Kits" / "8.1" / "bin",
    ]
    arch_dir = "x64" if arch.lower() == "x64" else "x86"
    for base in bases:
        # Windows 10: ...\bin\<sdkVersion>\<arch>\signtool.exe
        candidates.extend(glob.glob(str(base / "*" / arch_dir / "signtool.exe")))
        # Windows 8.1: ...\bin\<arch>\signtool.exe
        candidates.extend(glob.glob(str(base / arch_dir / "signtool.exe")))

    if candidates:
        # Берём самый "новый" по строковой сортировке пути
        candidates.sort()
        return candidates[-1]

    die("Не удалось найти signtool.exe. Установите Windows SDK или укажите путь через --signtool.")
    return ""  # недостижимо

def collect_files(paths: Iterable[Path], recursive: bool, include_exts: Tuple[str, ...]) -> List[Path]:
    files: List[Path] = []
    for p in paths:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            if recursive:
                for ext in include_exts:
                    files.extend(p.rglob(f"*{ext}"))
            else:
                for ext in include_exts:
                    files.extend(p.glob(f"*{ext}"))
        else:
            # Поддержка glob‑шаблонов в аргументах
            matched = [Path(s) for s in glob.glob(str(p))]
            for m in matched:
                if m.is_file():
                    files.append(m)
                elif m.is_dir():
                    if recursive:
                        for ext in include_exts:
                            files.extend(m.rglob(f"*{ext}"))
                    else:
                        for ext in include_exts:
                            files.extend(m.glob(f"*{ext}"))
    # Уникализируем и сортируем для стабильности
    uniq = sorted(set(f.resolve() for f in files))
    return uniq

def format_cmd_safe(cmd: Sequence[str]) -> str:
    """Строка команды для лога без вывода пароля (аргумент после '/p')."""
    safe = []
    hide_next = False
    for part in cmd:
        if hide_next:
            safe.append("***")
            hide_next = False
            continue
        safe.append(part)
        if part.lower() == "/p":
            hide_next = True
    return " ".join(f'"{c}"' if " " in c and not c.startswith('"') else c for c in safe)

def run_cmd(cmd: Sequence[str]) -> CompletedProcess:
    return run(cmd, stdout=PIPE, stderr=PIPE, text=True, shell=False)

def verify_signed(signtool: str, file: Path) -> Tuple[bool, str]:
    cmd = [signtool, "verify", "/pa", "/v", str(file)]
    proc = run_cmd(cmd)
    ok = proc.returncode == 0
    output = (proc.stdout or "") + (proc.stderr or "")
    return ok, output.strip()

def sign_step(
    signtool: str,
    pfx: str,
    pfx_pass: str,
    file: Path,
    fd_alg: str,
    description: Optional[str],
    description_url: Optional[str],
    timestamp_mode: Optional[str],  # "rfc3161" | "legacy" | None
    tr_url: Optional[str],
    legacy_t_url: Optional[str],
    append_signature: bool,
    verbose_signtool: bool,
    what_if: bool,
) -> Tuple[bool, str, str]:
    """
    Выполняет один шаг подписи (например, SHA1 или SHA256).
    Возвращает (ok, stdout+stderr, safe_cmd_string).
    """
    cmd: List[str] = [signtool, "sign", "/f", pfx, "/p", pfx_pass, "/fd", fd_alg]
    if description:
        cmd += ["/d", description]
    if description_url:
        cmd += ["/du", description_url]

    if timestamp_mode == "rfc3161" and tr_url:
        cmd += ["/tr", tr_url, "/td", "sha256"]
    elif timestamp_mode == "legacy" and legacy_t_url:
        cmd += ["/t", legacy_t_url]

    if append_signature:
        cmd.append("/as")

    if verbose_signtool:
        cmd.append("/v")

    cmd.append(str(file))
    safe = format_cmd_safe(cmd)

    if what_if:
        return True, f"[WHAT-IF] {safe}", safe

    proc = run_cmd(cmd)
    ok = proc.returncode == 0
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return ok, output, safe

def sign_file(file: Path, opt: Options) -> SignResult:
    try:
        if opt.skip_signed:
            ok_now, out_now = verify_signed(opt.signtool, file)
            if ok_now:
                return SignResult(file, ok=True, skipped=True, message="Уже подписан (verify OK).")

        # Конфигурация временных меток
        use_rfc3161 = not opt.no_timestamp and opt.tr_url
        use_legacy = not opt.no_timestamp and opt.legacy_t_url

        if opt.dual:
            # Шаг 1: SHA1 подпись (желательно со старой меткой /t)
            ok1, out1, cmd1 = sign_step(
                signtool=opt.signtool,
                pfx=opt.pfx,
                pfx_pass=opt.pfx_pass,
                file=file,
                fd_alg="sha1",
                description=opt.description,
                description_url=opt.description_url,
                timestamp_mode="legacy" if use_legacy else ("rfc3161" if use_rfc3161 else None),
                tr_url=opt.tr_url,
                legacy_t_url=opt.legacy_t_url,
                append_signature=False if opt.replace_existing else True,  # если нужно заменить — не добавляем /as
                verbose_signtool=opt.verbose_signtool,
                what_if=opt.what_if,
            )
            logging.info("Dual step #1 (SHA1): %s", cmd1)
            if not ok1:
                return SignResult(file, ok=False, skipped=False, message=f"FAIL dual-step#1 (SHA1):\n{out1}")

            # Шаг 2: SHA256 добавлением подписи (+RFC3161 /tr по умолчанию)
            ok2, out2, cmd2 = sign_step(
                signtool=opt.signtool,
                pfx=opt.pfx,
                pfx_pass=opt.pfx_pass,
                file=file,
                fd_alg="sha256",
                description=opt.description,
                description_url=opt.description_url,
                timestamp_mode="rfc3161" if use_rfc3161 else ("legacy" if use_legacy else None),
                tr_url=opt.tr_url,
                legacy_t_url=opt.legacy_t_url,
                append_signature=True,  # dual: всегда добавляем вторую подпись
                verbose_signtool=opt.verbose_signtool,
                what_if=opt.what_if,
            )
            logging.info("Dual step #2 (SHA256): %s", cmd2)
            if not ok2:
                return SignResult(file, ok=False, skipped=False, message=f"FAIL dual-step#2 (SHA256):\n{out2}")
        else:
            # Обычная подпись SHA256
            ok, out, cmd = sign_step(
                signtool=opt.signtool,
                pfx=opt.pfx,
                pfx_pass=opt.pfx_pass,
                file=file,
                fd_alg="sha256",
                description=opt.description,
                description_url=opt.description_url,
                timestamp_mode="rfc3161" if use_rfc3161 else ("legacy" if use_legacy else None),
                tr_url=opt.tr_url,
                legacy_t_url=opt.legacy_t_url,
                append_signature=False if opt.replace_existing else True,  # добавление vs замена
                verbose_signtool=opt.verbose_signtool,
                what_if=opt.what_if,
            )
            logging.info("Sign (SHA256): %s", cmd)
            if not ok:
                return SignResult(file, ok=False, skipped=False, message=f"FAIL sign: {out}")

        if opt.verify and not opt.what_if:
            ok_v, out_v = verify_signed(opt.signtool, file)
            if not ok_v:
                return SignResult(file, ok=False, skipped=False, message=f"VERIFY FAIL:\n{out_v}")

        return SignResult(file, ok=True, skipped=False, message="OK")
    except Exception as e:
        return SignResult(file, ok=False, skipped=False, message=f"EXC: {e}")

def parse_args(argv: Optional[Sequence[str]] = None) -> Options:
    p = argparse.ArgumentParser(
        description="Подписывает файлы с помощью signtool.exe и сертификата .pfx.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--signtool", help="Путь к signtool.exe (если не в PATH)", default=None)
    p.add_argument("--arch", choices=["x64", "x86"], default="x64", help="Искать signtool под нужную архитектуру")
    p.add_argument("--pfx", required=True, help="Путь к .pfx сертификату")
    pw = p.add_argument_group("Пароль PFX")
    pw.add_argument("--pfx-pass", help="Пароль к .pfx (небезопасно - лучше использовать переменные окружения)")
    pw.add_argument("--pfx-pass-env", default="SIGN_PFX_PASS", help="Имя переменной окружения с паролем .pfx")

    p.add_argument("--input", nargs="+", required=True, help="Файл(ы), папка(и) или glob‑шаблоны для подписи")
    p.add_argument("--recursive", action="store_true", help="Рекурсивный поиск в каталогах")
    p.add_argument("--ext", nargs="+", default=list(DEFAULT_EXTS), help="Какие расширения файлов подписывать")

    p.add_argument("--verify", action="store_true", help="Проверить подпись signtool verify после подписи")
    p.add_argument("--skip-signed", action="store_true", default=True, help="Пропускать уже подписанные файлы")
    p.add_argument("--replace-existing", action="store_true", help="Заменить имеющиеся подписи (внимание!)")

    ts = p.add_argument_group("Настройки метки времени")
    ts.add_argument("--tr", dest="tr_url", default="http://timestamp.digicert.com",
                    help="RFC3161 timestamp server (/tr). Рекомендуется.")
    ts.add_argument("--t", dest="legacy_t_url", default="http://timestamp.digicert.com",
                    help="Legacy timestamp server (/t) — удобно для SHA1 в dual‑sign.")
    ts.add_argument("--no-timestamp", action="store_true", help="Не ставить метку времени (не рекомендуется)")

    p.add_argument("--dual", action="store_true", help="Dual‑sign: сначала SHA1, затем добавление SHA256")
    p.add_argument("--description", help="Текст описания файла (/d)")
    p.add_argument("--url", dest="description_url", help="URL продукта (/du)")

    p.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Параллелизм")
    p.add_argument("--what-if", action="store_true", help="Режим сухого прогона: только показать команды")
    p.add_argument("--verbose-signtool", action="store_true", help="Добавить /v к вызовам signtool")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = p.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")

    if not is_windows():
        die("Этот скрипт предназначен для Windows (signtool.exe).")

    signtool_path = find_signtool(args.signtool, args.arch)

    pfx = Path(args.pfx)
    if not pfx.is_file():
        die(f".pfx файл не найден: {pfx}")

    # Пароль: приоритет — явный, затем переменная окружения
    pfx_pass = args.pfx_pass if args.pfx_pass is not None else os.environ.get(args.pfx_pass_env or "")
    if pfx_pass is None:
        die("Не задан пароль .pfx. Укажите --pfx-pass или переменную окружения через --pfx-pass-env (по умолчанию SIGN_PFX_PASS).")

    input_paths = [Path(x) for x in args.input]
    include_exts = tuple(sorted(set(e.lower() if e.startswith(".") else f".{e.lower()}" for e in args.ext)))

    return Options(
        signtool=signtool_path,
        pfx=str(pfx),
        pfx_pass=pfx_pass,
        input_paths=input_paths,
        recursive=args.recursive,
        include_exts=include_exts,
        verify=args.verify,
        skip_signed=args.skip_signed and not args.replace_existing,
        replace_existing=bool(args.replace_existing),
        dual=bool(args.dual),
        tr_url=None if args.no_timestamp else args.tr_url,
        legacy_t_url=None if args.no_timestamp else args.legacy_t_url,
        no_timestamp=bool(args.no_timestamp),
        description=args.description,
        description_url=args.description_url,
        workers=max(1, int(args.workers or 1)),
        what_if=bool(args.what_if),
        arch=args.arch,
        verbose_signtool=bool(args.verbose_signtool),
    )

def main(argv: Optional[Sequence[str]] = None) -> int:
    opt = parse_args(argv)
    files = collect_files(opt.input_paths, opt.recursive, opt.include_exts)
    if not files:
        logging.warning("Файлов для подписи не найдено (фильтр расширений: %s).", ", ".join(opt.include_exts))
        return 0

    logging.info("Найдено файлов: %d", len(files))
    logging.info("signtool: %s", opt.signtool)
    if opt.what_if:
        logging.info("Режим WHAT-IF: подпись выполняться не будет, будут показаны команды.")

    results: List[SignResult] = []
    if opt.workers == 1:
        for f in files:
            results.append(sign_file(f, opt))
    else:
        with cf.ThreadPoolExecutor(max_workers=opt.workers) as ex:
            for res in ex.map(lambda f: sign_file(f, opt), files):
                results.append(res)

    # Итоги
    ok_cnt = sum(1 for r in results if r.ok and not r.skipped)
    skipped_cnt = sum(1 for r in results if r.skipped)
    fail_cnt = sum(1 for r in results if not r.ok)

    for r in results:
        status = "SKIP" if r.skipped else ("OK" if r.ok else "FAIL")
        logging.info("[%s] %s - %s", status, r.file, r.message if r.message else "")

    logging.info("Итог: OK=%d, SKIP=%d, FAIL=%d", ok_cnt, skipped_cnt, fail_cnt)
    return 0 if fail_cnt == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
