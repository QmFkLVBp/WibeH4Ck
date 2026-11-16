cd ~/Desktop/ASSets/WibeH4Ck
source .venv/bin/activate

# кольори + звіт за замовчуванням (wibeh4ck_report.txt)
python3 wibeh4ck.py -t https://target.htb --report

# звіт у конкретний файл
python3 wibeh4ck.py -t https://target.htb --report /tmp/box1.txt

# при пайпі в tee кольори авто-вимикаються — форсувати:
python3 wibeh4ck.py -t https://target.htb --report --color | tee /tmp/run.log

# вимкнути кольори явно
python3 wibeh4ck.py -t https://target.htb --no-color --report

# JSON досі доступний, якщо треба для скриптів:
python3 wibeh4ck.py -t https://target.htb --report --json /tmp/raw.json
