import random, time
import requests, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA_POOL = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]


class HTTP:
    def __init__(self, proxy=None, timeout=15, retries=2):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = timeout
        self.session.headers["Accept"] = "*/*"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.retries = retries
        self.rotate_ua()

    def rotate_ua(self):
        self.session.headers["User-Agent"] = random.choice(UA_POOL)

    def get(self, url, **kw):
        return self._req("GET", url, **kw)

    def post(self, url, **kw):
        return self._req("POST", url, **kw)

    def _req(self, method, url, **kw):
        kw.setdefault("allow_redirects", True)
        kw.setdefault("timeout", self.session.timeout)
        last = None
        for attempt in range(self.retries + 1):
            try:
                return self.session.request(method, url, **kw)
            except requests.exceptions.RequestException as e:
                last = e
                if attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))
        raise last
