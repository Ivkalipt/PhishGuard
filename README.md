# PhishGuard

Локальная система **PhishGuard** анализирует текст сообщений и ссылки, поступающие через буфер обмена, с помощью наборов правил анализа текста, регулярных выражений и проверки доменных имён определяет вероятность фишингового характера сообщения и предупреждает пользователя

---

## 🚀 Возможности

- 📩 Анализ произвольного текста (сообщения, письма, уведомления)
- 🔗 Детальный анализ URL:
  - IP вместо домена
  - Punycode (xn--)
  - `@` в URL
  - подозрительные пути (`login`, `verify`, `token`, …)
  - избыточные поддомены
  - перенаправления
- 🧠 Лингвистический анализ:
  - ключевые фишинговые слова
  - социальная инженерия
  - смешение кириллицы и латиницы (Unicode-гомография)
- 💳 Обнаружение последовательностей, похожих на номера банковских карт
- 📊 Скоринговая система риска (0–100 %)
- 🧾 Понятный текстовый отчёт с объяснением причин
- 🌐 Опциональная интеграция с **urlscan.io**
- 📋 Проверка текста из буфера обмена (через `pyperclip`)

---

## 🧩 Архитектура

Проект реализован на Python с использованием объектно-ориентированного подхода и `dataclasses`.

Основные компоненты:

- `AppConfig` — конфигурация приложения
- `PhishGuard` — основной анализатор
- `UrlAnalysis` — результат анализа одной ссылки
- `TextAnalysis` — результат анализа текста
- `UrlScanClient` — клиент API urlscan.io

---

## ⚙️ Установка

### Клонирование репозитория

```bash
git clone https://github.com/Ivkalipt/PhishGuard.git
cd PhishGuard
python3 phishguard_main.py
```

### Установка зависимостей

```bash
pip install requests
```

### Проверка буфера обмена (опционально):

```bash
pip install pyperclip
```

### 🛠 Конфигурация (config.ini)

```ini
[KEYWORDS]
words =
    сроч
    немедл
    важн
    вниман
    предупрежд
    уведомл
    подтвержд
    треб
    необходим
    действ
    аккаунт
    учетн
    профил
    страниц
    пользоват
    клиент
    доступ
    вход
    авторизац
    аутентификац
    логин
    парол
    код
    одноразов
    sms
    смс
    pin
    token
    ключ
    безопасн
    защит
    провер
    верификац
    восстанов
    сброс
    reset
    restore
    recover
    verify
    confirm
    secure
    security
    update
    upgrade
    validate
    login
    signin
    password
    passcod
    credential
    account
    user
    session
    access
    block
    suspend
    limit
    restrict
    lock
    disable
    заблокир
    огранич
    приостанов
    отключ
    истек
    срок
    нарушен
    подозрит
    необычн
    активн
    попыт
    вход
    нов
    регион
    неизвестн
    риск
    угроз
    компромет
    мошеннич
    fraud
    scam
    phishing
    identity
    urgent
    immediate
    action
    click
    нажм
    перейт
    ссылк
    открыт
    download
    загруз
    установ
    install
    check
    review
    сейчас
    ваш
    платеж
    оплат
    транзакц
    перевод
    списан
    возврат
    refund
    payment
    billing
    invoice
    charge
    balance
    счет
    карт
    банк
    финанс
    средств
    деньг
    выигр
    приз
    подар
    вознагражден
    бонус
    купон
    сертификат
    voucher
    reward
    prize
    winner
    congrat
    получ
    claim
    free
    бесплатн
    ограничен
    предлож
    акц
    розыгрыш
    лотере
    survey
    опрос
    форм
    данн
    информац
    персональн
    паспорт
    снилс
    инн
    номер
    cvc
    cvv
    expir
    support
    help
    центр
    техподдержк
    администратор
    system
    official
    trusted
    verify
    confirm

[SUFFIXES]
suff = 
    иями
    ями
    ами
    ями
    ение
    ения
    ений
    овать
    ировать
    ить
    ать
    ять
    ымиими
    ого
    ему
    ому
    ая
    яя
    ое
    ее
    ов
    ев
    ам
    ям
    ах
    ях
    ый
    ий
    ой
    а
    я
    о
    е
    ы
    и
    у

[BAD_DOMAINS]
domains =
    vk-verification.ru
    paypa1.com
    secure-login.net
    malicious-example.com

[API]
auth_key = <Your api key>

[CHECK]
only_local_check = 0
```
