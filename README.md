# WibeH4Ck

Модульний термінальний фреймворк для HTB/THM: Bloody Cyan банери, меню модулів, контекстний prompt і Tab-доповнення.

![Головна консоль](docs/console.png)

## Запуск

```bash
git clone https://github.com/QmFkLVBp/WibeH4Ck.git
cd WibeH4Ck
python3 rce.py
```

Саме `python3 rce.py` відкриває інтерактивну консоль. `--help` показує довідку щодо аргументів запуску.

```bash
python3 rce.py --help
python3 rce.py -l
python3 rce.py --no-color
python3 rce.py --no-banner
```

Для інтерфейсу достатньо стандартної бібліотеки Python 3. Арти вже включені в репозиторій: інтернет, pyfiglet і rich для них не потрібні. Кольори автоматично вимикаються при перенаправленні виводу, через `NO_COLOR` або `--no-color`.

## Робота в консолі

Введи номер із меню або назву модуля:

```text
use revshell
set LHOST 127.0.0.1
set LPORT 4444
show options
```

Вибір модуля показує його Bloody-арт, опис та опції. Виконання починається лише після окремої команди `run`, `exploit` або `x`.

![Екран модуля](docs/revshell.png)

| Команда | Дія |
| --- | --- |
| `menu` | Меню з номерами модулів |
| `home` | Головний екран; знімає вибір модуля |
| `modules` | Усі модулі з категоріями та описами |
| `search <текст>` | Пошук за назвою, категорією чи описом |
| `use <назва або номер>` | Вибір модуля |
| `info` | Арт та опис поточного модуля |
| `show options` / `options` | Поточні значення й обов’язкові опції |
| `set <OPT> <значення>` | Задати опцію |
| `unset <OPT>` | Очистити опцію |
| `run` / `exploit` / `x` | Перевірити опції та виконати модуль |
| `listener <порт>` | Запустити наявний TCP-listener |
| `back` | Вивантажити поточний модуль |
| `banner` / `clear` | Повторити арт / перемалювати екран |
| `exit` / `quit` | Вийти |

Tab доповнює команди, назви модулів після `use` і назви опцій після `set`/`unset`. Контекст у prompt показує шлях поточного модуля.

## Модулі й арти

| Модуль | Категорія | Bloody-арт |
| --- | --- | --- |
| `cve_2019_11043` | PHP / FPM | PHP FPM |
| `cve_2024_4577` | PHP / Windows | PHP CGI |
| `log4shell` | Java / Log4j | LOG4SHELL |
| `revshell` | Payload / Shell | REVSHELL |

Режим `-m <модуль> -o K=V` збережений. Наявні PoC-обгортки використовують свої попередні зовнішні вимоги; зміни інтерфейсу їх не встановлюють і не запускають.

## Перевірка

```bash
python3 -W error -m py_compile rce.py framework.py terminal_ui.py modules/*.py
python3 -W error -m unittest discover -s tests -v
python3 rce.py -l
```

Перевірки охоплюють запуск, завантаження чотирьох модулів, меню, опції, доповнення, обробку некоректних лапок і ширину термінала. Експлойти не виконуються.

## Новий модуль

1. Скопіюй `modules/_template.py` у `modules/<назва>.py`.
2. Заповни `name`, `description`, `options` та `run()`.
3. Перезапусти консоль.

Для окремої категорії й арту додай запис у `MODULE_STYLE` у `terminal_ui.py`. Вузький термінал або непідтримуваний символ отримує читабельний текстовий заголовок.

Гліфи й cyan-палітра: [TAAG, Bloody / TheDraw](https://patorjk.com/software/taag/). Цифра `4` додана локально, оскільки вихідний шрифт не містить цифр. Деталі — в [assets/README.md](assets/README.md).
