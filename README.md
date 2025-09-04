# PFX SignTool — автоматическая подпись Windows‑бинарников через `signtool.exe`

Готовый CLI‑скрипт на Python для подписи `.exe/.dll/.msi/.msix/.appx` и др. с помощью сертификата `.pfx`.
Умеет автоматически находить `signtool.exe`, ставить метки времени (RFC3161 `/tr` и legacy `/t`), делать dual‑sign (SHA1+SHA256), пропускать уже подписанные файлы и проверять подпись.

> Требования: Windows, установленный Windows SDK (в составе есть `signtool.exe`), Python 3.8+.

---

## Установка

Просто скачайте `sign_with_pfx.py` (или клонируйте репозиторий).

```bat
git clone https://github.com/<your-account>/pfx-signtool.git
cd pfx-signtool
```

> **Безопасность:** не храните `.pfx` и пароли в репозитории. Используйте переменные окружения/секреты CI.

---

## Быстрый старт

1) Установите Windows SDK (должен быть `signtool.exe`).  
2) Экспортируйте пароль `.pfx` как переменную окружения:
```bat
set SIGN_PFX_PASS=мой_секретный_пароль
```
3) Подпишите файлы:
```bat
python sign_with_pfx.py --pfx C:\certs\release.pfx --pfx-pass-env SIGN_PFX_PASS --input dist\MyApp.exe --verify
```

Подписать всё в папке рекурсивно:
```bat
python sign_with_pfx.py --pfx C:\certs\release.pfx --pfx-pass-env SIGN_PFX_PASS --input dist\ --recursive --verify
```

---

## Частые сценарии

**Dual‑sign (SHA1 → затем добавление SHA256)**
```bat
python sign_with_pfx.py ^
  --pfx C:\certs\release.pfx --pfx-pass-env SIGN_PFX_PASS ^
  --input dist\ --recursive --dual ^
  --t http://timestamp.digicert.com ^
  --tr http://timestamp.digicert.com ^
  --verify
```

**Явный путь к signtool.exe**
```bat
python sign_with_pfx.py --signtool "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" ^
  --pfx C:\certs\release.pfx --pfx-pass-env SIGN_PFX_PASS --input dist\MyApp.exe
```

**Сухой прогон (без фактической подписи)**
```bat
python sign_with_pfx.py --pfx C:\certs\release.pfx --pfx-pass-env SIGN_PFX_PASS ^
  --input dist\MyApp.exe --what-if
```

---

## Ключевые опции

- `--input` — файл/папка/маска (`glob`). Для папок добавьте `--recursive`.
- `--ext` — список расширений (по умолчанию: `.exe .dll .sys .msi .msix .msixbundle .appx .appxbundle`).
- `--verify` — запуск `signtool verify` после подписи.
- `--dual` — сначала подпись SHA1 (опц. `/t`), затем добавление SHA256 (с `/tr`).
- `--tr` — RFC3161 timestamp server (рекомендуется).
- `--t` — legacy timestamp server (удобно для шага SHA1).
- `--description`, `--url` — описание и ссылка продукта.
- `--workers` — параллельная подпись нескольких файлов.
- `--replace-existing` — заменить имеющиеся подписи (в противовес «добавлению» `/as`).
- `--what-if` — показать команды, не выполняя их.

> Примечание: скрипт по умолчанию **пропускает уже подписанные** файлы. Чтобы принудительно переподписать — используйте `--replace-existing`.

---

## GitHub Actions (CI)

В репозитории есть два workflow:

### 1) `.github/workflows/ci.yml` — быстрый smoke‑тест

- Не требует реального `signtool.exe` и сертификата.
- Создаёт «фиктивные» файлы и запускает скрипт в режиме `--what-if --replace-existing`,
  указывая любой существующий бинарник как `--signtool` (например, `C:\Windows\System32\cmd.exe`), чтобы пройти валидацию пути.

### 2) `.github/workflows/release-sign-example.yml` — пример реального подписания

- Запускается на `windows-latest`.
- Ожидает, что вы положили в **Secrets**:
  - `PFX_BASE64` — содержимое `.pfx` в base64,
  - `PFX_PASSWORD` — пароль от `.pfx`.
- Декодирует сертификат, находит `signtool`, подписывает артефакты из `dist\`.

Оба workflow лежат в репо и готовы к использованию/кастомизации.

---

## Практические советы

- Всегда ставьте метку времени (RFC3161 через `--tr`), чтобы подписи оставались валидными после истечения сертификата.
- Если `verify` падает на CI — часто виноваты сетевые ограничения до CRL/OCSP или недоступность timestamp‑сервера.
- Никогда не коммитьте `.pfx`. Для CI используйте secrets + временный файл (см. пример workflow).

---

## Лицензия

MIT — см. файл [LICENSE](./LICENSE).
