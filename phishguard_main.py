import re
import sys
import time
import json
import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from urllib.parse import urlparse, urlunparse

import requests


# =========================
# Конфиг и модели данных
# =========================

@dataclass(frozen=True)
class AppConfig:
    auth_key: str
    only_local_check: bool
    suspicious_keywords: List[str]
    known_bad_domains: List[str]
    suffixes: List[str]


@dataclass
class UrlAnalysis:
    original: str
    final_url: str
    score: int
    findings: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    urlscan_report_url: Optional[str] = None
    urlscan_meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TextAnalysis:
    text: str
    score: int
    level: str
    findings: List[str] = field(default_factory=list)
    url_analyses: List[UrlAnalysis] = field(default_factory=list)


# =========================
# Утилиты
# =========================

URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)'
    r'(?:[^\s()<>]+|$([^\s()<>]+|(\([^\s()<>]+$))*\))+)'
)

IPV4_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def extract_urls(text: str) -> List[str]:
    return [m[0] for m in URL_REGEX.findall(text)]


def is_ipv4(host: str) -> bool:
    return bool(IPV4_REGEX.match(host or ""))


def is_punycode(domain: str) -> bool:
    return "xn--" in (domain or "").lower()


def has_suspicious_unicode_mix(text: str) -> bool:
    """
    Проверяем подмену unicode
    """
    cyr_confusables = set("аеорсубх")
    if not re.search(r"[A-Za-z]", text):
        return False
    for ch in text:
        if ch.lower() in cyr_confusables:
            return True
    return False


def ensure_scheme(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if re.match(r"^[a-zA-Z]+://", url):
        return url
    return "https://" + url


def safe_hostname(parsed) -> str:
    try:
        return parsed.hostname or ""
    except Exception:
        return ""


# =========================
# Работа с urlscan.io
# =========================

class UrlScanClient:
    def __init__(self, api_key: str, session: Optional[requests.Session] = None):
        self.api_key = api_key
        self.session = session or requests.Session()

    def submit_scan(self, url: str) -> Tuple[int, Optional[str], Optional[str]]:
        """
        (http_status, uuid, error_text)
        """
        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "public"}
        try:
            resp = self.session.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload, timeout=10)
            if resp.status_code != 200:
                return resp.status_code, None, resp.text
            data = resp.json()
            return 200, data.get("uuid"), None
        except requests.RequestException as e:
            return 0, None, str(e)

    def poll_result(self, uuid: str, timeout_s: int = 35, poll_every_s: float = 2.5) -> Tuple[int, Dict[str, Any]]:
        """
        (http_status, json)
        200 если готово, 404/other если не готово/ошибка.
        """
        deadline = time.time() + timeout_s
        last_status = 0
        while time.time() < deadline:
            try:
                resp = self.session.get(f"https://urlscan.io/api/v1/result/{uuid}/", timeout=10)
                last_status = resp.status_code
                if resp.status_code == 200:
                    return 200, resp.json()
            except requests.RequestException:
                last_status = 0
            time.sleep(poll_every_s)
        return last_status or 0, {}


# =========================
# Основной анализатор
# =========================

class PhishGuard:

    W_KEYWORDS = 6
    CAP_KEYWORDS = 30

    W_UNICODE_MIX = 25

    W_CARD = 60

    URL_RISK_MULTIPLIER = 0.75
    URL_RISK_CAP = 75            # огр. вклада

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.urlscan = UrlScanClient(cfg.auth_key, self.session) if (cfg.auth_key and not cfg.only_local_check) else None

    def resolve_redirects(self, url: str, timeout: int = 7, max_redirects: int = 5) -> Tuple[str, List[str], Optional[str]]:
        try:
            resp = self.session.get(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={"User-Agent": "PhishGuard"},
            )
            if len(resp.history) > max_redirects:
                return url, [r.url for r in resp.history], "слишком много перенаправлений"
            return resp.url, [r.url for r in resp.history], None
        except requests.RequestException as e:
            return url, [], str(e)

    def analyze_url(self, raw_url: str) -> UrlAnalysis:
        original = raw_url.strip()
        score = 0
        findings: List[str] = []

        # приводим к норм виду
        candidate = ensure_scheme(original)

        # пробуем редиректы, если разрешено
        final_url = candidate
        chain: List[str] = []
        redir_error: Optional[str] = None

        if not self.cfg.only_local_check:
            final_url, chain, redir_error = self.resolve_redirects(candidate)
            if redir_error:
                findings.append(f"Сайт недоступен / ошибка запроса: {redir_error}")

        # парсим
        try:
            parsed = urlparse(final_url)
        except Exception:
            return UrlAnalysis(
                original=original,
                final_url=final_url,
                score=5,
                findings=["Невозможно разобрать URL"],
            )

        host = safe_hostname(parsed).lower()
        netloc = (parsed.netloc or "")
        path = (parsed.path or "")
        full = parsed.geturl()

        # ---- urlscan (если доступно)
        urlscan_report_url = None
        urlscan_meta: Dict[str, Any] = {}
        if self.urlscan is not None:
            st, uuid, err = self.urlscan.submit_scan(final_url)
            if st != 200 or not uuid:
                findings.append(f"urlscan: ошибка отправки ({st})")
                if err:
                    findings.append(f"urlscan: {err.strip()[:200]}")
            else:
                st2, data = self.urlscan.poll_result(uuid)
                if st2 != 200:
                    findings.append(f"urlscan: результат не получен ({st2})")
                else:
                    verdict = data.get("verdicts", {}).get("overall", {}) or {}
                    page = data.get("page", {}) or {}
                    task = data.get("task", {}) or {}

                    urlscan_report_url = task.get("reportURL")
                    urlscan_meta = {
                        "ip": page.get("ip"),
                        "country": page.get("country"),
                        "urlscan_score": verdict.get("score", 0),
                        "malicious": verdict.get("malicious"),
                    }

                    raw = verdict.get("score", 0)
                    try:
                        raw = float(raw)
                    except Exception:
                        raw = 0.0
                    mapped = int(clamp(raw, -100, 100))
                    urlscan_points = int(clamp(mapped, 0, 100) * 0.30)
                    if urlscan_points:
                        findings.append(f"urlscan: обнаружены признаки риска (вклад {urlscan_points} баллов)")
                    score += urlscan_points

        # Чёрный список доменов
        if host and host in self.cfg.known_bad_domains:
            findings.append(f"Домен в чёрном списке: {host}")
            score += 70

        if is_ipv4(host):
            findings.append(f"Используется IP вместо доменного имени: {host}")
            score += 30

        if len(full) > 120:
            findings.append(f"Длинный URL ({len(full)} символов) — часто используется для маскировки")
            score += 15

        if "@" in netloc or "@" in path:
            findings.append("Символ '@' в URL — возможно попытка скрыть истинный адрес")
            score += 40

        if is_punycode(host):
            findings.append("Punycode/IDN в домене (xn--) — возможный гомограф-домен")
            score += 35

        if host.count(".") >= 3:
            findings.append(f"Много уровней домена: {host} — возможная маскировка основного домена")
            score += 10

        if re.search(r"(login|signin|verify|confirm|password|token)", path, flags=re.I) or \
           re.search(r"(login|signin|verify|confirm|password|token)", parsed.query, flags=re.I):
            findings.append("В URL есть признаки страниц входа/подтверждения — типично для фишинга")
            score += 25

        if "%" in full or re.search(r"(?i)(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|%6a%61%76%61%73%63%72%69%70%74|&#x?[0-9a-f]+;?)\s*:", full, flags=re.I):
            findings.append("Есть escape-последовательности (%) или javascript-выражения — подозрительно")
            score += 10

        # Редирект чек
        if final_url != candidate and chain:
            findings.append("Обнаружено перенаправление на другой URL")
            score += 20

        score = int(clamp(score, 0, 100))
        return UrlAnalysis(
            original=original,
            final_url=final_url,
            score=score,
            findings=findings,
            redirect_chain=chain,
            urlscan_report_url=urlscan_report_url,
            urlscan_meta=urlscan_meta,
        )

    def analyze_text(self, text: str) -> TextAnalysis:
        findings: List[str] = []
        score = 0

        lowered = text.lower()

        # 1) ключевые слова
        keyword_hits: List[str] = []
        for kw in self.cfg.suspicious_keywords:
            for suff in self.cfg.suffixes:
                w = (kw + suff).strip()
                if w and w in lowered:
                    keyword_hits.append(w)

        if keyword_hits:
            hits_preview = ", ".join(keyword_hits[:8])
            findings.append(f"Подозрительные ключевые слова в тексте: {hits_preview}")
            score += int(clamp(self.W_KEYWORDS * len(keyword_hits), 0, self.CAP_KEYWORDS))

        # 2) unicode-гомография
        if has_suspicious_unicode_mix(text):
            findings.append("Смешение похожих символов Unicode (возможная гомография)")
            score += self.W_UNICODE_MIX

        # 3) номер карты
        if re.findall(r"\b(?:\d[ -]?){13,19}\b", text):
            findings.append("Похоже на номер карты (13–19 цифр) — крайне подозрительно")
            score += self.W_CARD

        # 4) ссылки
        urls = extract_urls(text)
        url_analyses: List[UrlAnalysis] = []
        if urls:
            for u in urls:
                url_analyses.append(self.analyze_url(u))

            max_url_risk = max((ua.score for ua in url_analyses), default=0)
            url_component = int(clamp(max_url_risk * self.URL_RISK_MULTIPLIER, 0, self.URL_RISK_CAP))
            score += url_component
            findings.append(f"Ссылки: найдено {len(urls)}; максимальный риск по URL = {max_url_risk}%, вклад в общий риск = {url_component}")
        else:
            if score > 0:
                score += 5

        score = int(clamp(score, 0, 100))
        level = self.risk_level(score)

        return TextAnalysis(
            text=text,
            score=score,
            level=level,
            findings=findings,
            url_analyses=url_analyses,
        )

    @staticmethod
    def risk_level(score: int) -> str:
        if score >= 75:
            return "ВЫСОКИЙ"
        if score >= 40:
            return "СРЕДНИЙ"
        return "НИЗКИЙ"


# =========================
# Красивый вывод
# =========================

def print_text_report(ta: TextAnalysis) -> None:
    print("=" * 72)
    print("PHISHGUARD REPORT")
    print("-" * 72)
    preview = ta.text.strip().replace("\n", " ")
    if len(preview) > 500:
        preview = preview[:500] + "…"
    print(f"Текст: {preview}")
    print("-" * 72)
    print(f"Оценка риска: {ta.score}%")
    if ta.level == "ВЫСОКИЙ":
        print("Уровень: ВЫСОКИЙ — вероятно фишинг. Не переходите по ссылкам и не вводите данные.")
    elif ta.level == "СРЕДНИЙ":
        print("Уровень: СРЕДНИЙ — проявите осторожность.")
    else:
        print("Уровень: НИЗКИЙ — скорее безопасно, но будьте внимательны.")

    if ta.findings:
        print("\nОбнаруженные признаки:")
        for f in ta.findings:
            print(f"  • {f}")

    if ta.url_analyses:
        print("\nРазбор ссылок:")
        for i, ua in enumerate(ta.url_analyses, 1):
            print("-" * 72)
            print(f"[{i}] {ua.original}")
            if ua.final_url and ua.final_url != ua.original:
                print(f"    Final: {ua.final_url}")
            print(f"    Риск по URL: {ua.score}%")

            if ua.redirect_chain:
                chain_preview = " -> ".join(ua.redirect_chain[:5])
                if len(ua.redirect_chain) > 5:
                    chain_preview += " -> …"
                print(f"    Редиректы: {chain_preview}")

            if ua.urlscan_meta:
                ip = ua.urlscan_meta.get("ip")
                country = ua.urlscan_meta.get("country")
                us = ua.urlscan_meta.get("urlscan_score")
                mal = ua.urlscan_meta.get("malicious")
                print(f"    urlscan: ip={ip}, country={country}, score={us}, malicious={mal}")

            if ua.urlscan_report_url:
                print(f"    urlscan report: {ua.urlscan_report_url}")

            if ua.findings:
                for it in ua.findings:
                    print(f"    • {it}")
    print("=" * 72)
    print()


# =========================
# Загрузка конфига
# =========================

def load_config(config_path: Path) -> AppConfig:
    if not config_path.exists():
        raise FileNotFoundError("config.ini не найден")

    cp = configparser.ConfigParser()
    cp.read(config_path, encoding="utf-8")

    # проверяем обязательные секции
    required_sections = {"API", "CHECK", "KEYWORDS", "SUFFIXES", "BAD_DOMAINS"}
    missing = [s for s in required_sections if s not in cp]
    if missing:
        raise configparser.NoSectionError(f"Не все блоки указаны в config.ini. Отсутствуют: {', '.join(missing)}")

    auth_key = cp.get("API", "auth_key", fallback="").strip()
    only_local_check = bool(int(cp.get("CHECK", "only_local_check", fallback="0")))

    suspicious_keywords = [
        w.strip() for w in cp.get("KEYWORDS", "words", fallback="").splitlines() if w.strip()
    ]
    known_bad_domains = [
        d.strip().lower() for d in cp.get("BAD_DOMAINS", "domains", fallback="").splitlines() if d.strip()
    ]
    suffixes = [
        s.strip().lower() for s in cp.get("SUFFIXES", "suff", fallback="").splitlines() if s.strip()
    ]

    return AppConfig(
        auth_key=auth_key,
        only_local_check=only_local_check,
        suspicious_keywords=suspicious_keywords,
        known_bad_domains=known_bad_domains,
        suffixes=suffixes,
    )


# =========================
# main
# =========================

def main() -> None:
    config_path = Path("config.ini")

    try:
        cfg = load_config(config_path)
    except configparser.NoSectionError as e:
        print(str(e))
        return
    except FileNotFoundError as e:
        print(str(e))
        return
    except Exception as e:
        print(f"Ошибка чтения config.ini: {e}")
        return

    # clipboard
    try:
        import pyperclip  # type: ignore
        clipboard_available = True
    except Exception:
        pyperclip = None  # type: ignore
        clipboard_available = False

    guard = PhishGuard(cfg)

    samples = [
        "У вас новое сообщение ВКонтакте: https://xn--vk-1cd.com/messages?auth=token_secure",
        "Системное уведомление: обнаружен вход с нового устройства. Подтвердите активность: http://185.231.154.2/verify?user=client123",
        "Ваш аккаунт Google требует верификации. Перейдите: https://gооgle-security.com/confirm",
        "PAYPAL NOTICE: Your account has been limited. Verify your identity: https://paypa1-secure.com/restore?id=789456123",
        "Ваша карта заблокирована. Для разблокировки сообщите данные: 4890 4701 2345 6789 срок 05/28 CVV 123",
        "Ваша посылка задерживается. Отследить: https://tracking.russian-post.delivery.secure-update.com/parcel?id=ZXCV123",
        "Проверьте документ: https://docs.company.com/view?doc=javascript:alert('phish')",
        "Ваш аккаунт ВКонтакте заблокирован! Подтвердите личность: https://vk-verification.ru/login?token=abc123",
        "СРОЧНО! Ваш банковский счет заблокирован! Немедленно позвоните для подтверждения: 7702 4200 3096 3245 4334",
        "Посмотри это видео: https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "Привет, как дела? Давай встретимся завтра в 18:00 в кафе на Ленина.",
        "Вы выиграли iPhone 15! Получите приз: https://bit.ly/3xY7zKm",
        "ФНС: У вас есть недоплата налога 5 847 руб. Оплатите до завтра: https://xn--80aesfpebagmfblc0a.xn--p1ai-tax.ru/payment",
        "Вам доступен бонус: https://microsoft.com:@hack-site.biz/reward",
        "Для подтверждения заказа войдите по ссылке: https://ozon.ru/login?redirect=evil-site.com/steal",
        "Привет! Посмотри мое новое видео на YouTube: https://youtu.be/abc123. Кстати, твой Instagram взломали: https://instagrarn-security.com/recover",
        "СРОЧНО! ПАРОЛЬ СКОМПРОМЕТИРОВАН! ВЕРИФИКАЦИЯ ТРЕБУЕТСЯ НЕМЕДЛЕННО!",
        "Доступ к корпоративному серверу: http://192.168.1.1:8080/admin/login",
        "Здравствуй, Кирилл! Это Сартасова Марина Юрьевна. Поздравляю, ты прошел на ВКОШП. Срочно нужно купить билеты. Переводите деньги на карту 7702 4200 3096 3245. Подтвердите платеж: https://fake-bank-transfer.ru/confirm?amount=1000000",
        "СБЕРБАНК: Ваша карта заблокирована! Немедленно подтвердите данные: https://xn--80aesfpebagmfblc0a.xn--p1ai-secure.com/login?card=123456&redirect=http://phish-site.net/steal",
    ]

    for s in samples:
        report = guard.analyze_text(s)
        print_text_report(report)

    if clipboard_available:
        print("Мониторинг буфера обмена (однократная проверка текущего содержимого)")
        try:
            last = pyperclip.paste()
            report = guard.analyze_text(last)
            print_text_report(report)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Ошибка чтения буфера обмена: {e}")
    else:
        print("pyperclip не установлен — установите 'pyperclip' для проверки буфера обмена.")


if __name__ == "__main__":
    main()
