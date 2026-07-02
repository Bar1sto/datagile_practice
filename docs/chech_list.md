## что уже сделано по ТЗ

### 1. источник NVD

**сделано**

- [x] `NvdClient`
- [x] NVD API key из `.env`
- [x] base URL из `.env`
- [x] pagination через `startIndex` / `resultsPerPage`
- [x] timeout
- [x] retry для timeout/network ошибок
- [x] retry для HTTP `429`, `502`, `503`, `504`
- [x] реальные запросы к NVD проверены

проверено:

- [x] sync за 1 день
- [x] sync chunks по 7 дней
- [x] initial load за 1 месяц
- [x] scheduler recent sync
- [x] manual recent sync

---

### 2. Initial load

**базово сделано**

- [x] `sync_initial_load(months=...)`
- [x] разбиение периода на chunks
- [x] загрузка большого периода
- [x] upsert в `cve_records`
- [x] один `sync_run` на весь initial load
- [x] проверено на 1 месяце

проверенный результат:

```text
NvdSyncResult(total_count=8054, added_count=7365, updated_count=689)
```

осталось:

- [ ] прогнать 12 месяцев
- [ ] вынести `months`, `chunk_days`, timeout/retry config в настройки
- [ ] возможно заменить `months * 30` на точные месяцы через `relativedelta`

---

### 3. Daily scheduled sync

**сделано**

- [x] `NvdSyncScheduler`
- [x] APScheduler
- [x] FastAPI lifespan startup/shutdown
- [x] job запускается вместе с приложением
- [x] job корректно пишет `sync_runs`
- [x] проверено на коротком interval

### 4. Sync history / `sync_runs`

**сделано базово**

- [x] таблица `sync_runs`
- [x] `status`: `running` / `success` / `failed`
- [x] `added_count`
- [x] `updated_count`
- [x] `started_at`
- [x] `finished_at`
- [x] `GET /sync-runs/`
- [x] `GET /sync-runs/{sync_run_id}`
- [x] failed sync записывается

техдолг:

- [ ] failed flow должен обновлять тот же `running sync_run`, а не создавать новый после rollback
- [ ] унифицировать источник времени для `started_at` и `finished_at`
- [ ] добавить поле ошибки: `error_message` / `error_code`

---

### 5. No duplicates

**сделано**

- [x] `cve_id` unique
- [x] `get_by_cve_id`
- [x] `upsert_cve`
- [x] `CveUpsertResult`
- [x] повторный sync обновляет записи, а не создаёт дубликаты

проверено:

```text
первый sync  -> added
повторный    -> updated
manual sync  -> added=0, updated=406
```

---

### 6. Нормализация NVD CVE

**сделано**

- [x] `cve_id`
- [x] `source_identifier`
- [x] еnglish description
- [x] `published_at`
- [x] `last_modified_at`
- [x] `vuln_status`
- [x] CVSS v3.1
- [x] CVSS v3.0
- [x] CVSS v2
- [x] `cvss_base_score`
- [x] `cvss_base_severity`
- [x] `cvss_vector`

техдолг:

- [ ] заменить raw `dict` на typed object: `NormalizedCve`
- [ ] возможно сделать `NvdNormalizer` class
- [ ] добавить тесты нормализатора

---

### 7. CVE API

#### `GET /cve/{cve_id}`

**сделано**

- [x] поиск по `cve_id`
- [x] response schema
- [x] 404 если CVE не найден
- [x] Swagger docs

#### `GET /cve`

**частично сделано**

- [x] pagination
- [x] `limit`
- [x] `offset`
- [x] `severity`
- [x] `published_from`
- [x] `published_to`
- [x] date range validation
- [x] total count
- [x] paginated response

осталось:

- [ ] `vendor` filter
- [ ] `product` filter
- [ ] модель/таблица для affected products или временное упрощение

---

### 8. Stats API

**сделано**

- [x] `GET /stats`
- [x] `total_cves`
- [x] `by_severity`
- [x] `latest_published_at`
- [x] `latest_modified_at`

---

### 9. Unified error structure

**частично сделано**

- [x] `ErrorResponse` schema
- [x] `error_detail()` helper
- [x] Swagger error docs частично показываются

Сейчас runtime может возвращать:

```json
{
  "detail": {
    "error": {
      "code": "...",
      "message": "..."
    }
  }
}
```

надо

```json
{
  "error": {
    "code": "...",
    "message": "..."
  }
}
```

осталось:

- [ ] custom exception handler для `HTTPException`
- [ ] единый формат для validation errors, если хватит времени

---

### 10. Swagger / OpenAPI

**сделано базово**

- [x] FastAPI Swagger работает
- [x] основные response models есть
- [x] endpoints видны

улучшить:

- [ ] error responses везде
- [ ] descriptions для query params
- [ ] summaries для endpoints
- [ ] привести tags/names к аккуратному виду

---

### 11. Manual sync endpoint

**сделано**

- [x] `POST /sync-runs/nvd/recent?days=1`
- [x] вызывает `sync_recent`
- [x] пишет `sync_runs`
- [x] возвращает counters

результат

```json
{
  "total_count": 406,
  "added_count": 0,
  "updated_count": 406
}
```

осталось:

- [ ] ограничить `days` через `Query`: минимум 1, максимум 7
- [ ] позже можно сделать background запуск, чтобы HTTP request не висел долго

---

## Что осталось сделать до сдачи backend

### 1. Vendor/product filters

- [ ] как парсить CPE из NVD `configurations`
- [ ] где хранить affected products
- [ ] отдельная таблица или упрощённые поля
- [ ] как дедуплицировать пары `vendor/product`
- [ ] как фильтровать `GET /cve?vendor=...&product=...`
- [ ] таблица `cve_affected_products`
- [ ] связь с `cve_records`
- [ ] поля `vendor`, `product`, возможно `cpe_uri`

---

### 2. Unified error handler

- [ ] убрать внешний `detail`
- [ ] вернуть формат `{ "error": { "code": ..., "message": ... } }`
- [ ] проверить 404 по CVE
- [ ] проверить 404 по sync_run
- [ ] проверить date range validation

---

### 3. Tests

минимум

- [ ] normalizer tests
- [ ] repository upsert tests
- [ ] `GET /cve/{cve_id}` tests
- [ ] `GET /cve` pagination/filter tests
- [ ] `GET /stats` tests
- [ ] `GET /sync-runs` tests
- [ ] manual sync endpoint test with mocked client/service


- [ ] не бить реальный NVD API в unit tests
- [ ] использовать mock/fake данные

---

### 4. Docker / docker-compose

- [ ] Dockerfile для app
- [ ] docker-compose с PostgreSQL
- [ ] env variables
- [ ] инструкция запуска
- [ ] миграции через Alembic

---

### 5. README

- [ ] что делает проект
- [ ] stack
- [ ] как запустить локально
- [ ] как запустить через Docker
- [ ] как применить миграции
- [ ] как сделать initial load
- [ ] какие endpoints есть
- [ ] что реализовано
- [ ] что осталось / roadmap

---

### 6. 12-month initial load

- [ ] прогнать `sync_initial_load(months=12)`
- [ ] проверить время выполнения
- [ ] проверить количество CVE
- [ ] проверить, что repeated sync не создаёт дубликаты

---

## усложнение

### 1. OSV

- [ ] `OsvClient`
- [ ] `OsvNormalizer`
- [ ] source = `OSV`
- [ ] sync_runs для OSV
- [ ] дедупликация с NVD по CVE ID
- [ ] решить, что делать с vulnerabilities без CVE ID

---

### 2. ФСТЭК БДУ

- [ ] найти рабочий источник/формат данных
- [ ] `BduClient`
- [ ] `BduNormalizer`
- [ ] source = `BDU`
- [ ] mapping на общую модель
- [ ] дедупликация с NVD/OSV

---

### 3. Frontend

- [ ] React, если хватает времени
- [ ] Jinja2, если надо быстро и просто

минимум

- [ ] список CVE
- [ ] поиск/фильтры
- [ ] карточка CVE
- [ ] stats page

---

### 4. деплоу

- [ ] VPS / Render / Railway / другой вариант
- [ ] production env
- [ ] PostgreSQL
- [ ] миграции
- [ ] basic deployment instructions

---

## техдолг

- [ ] failed sync должен обновлять тот же `running sync_run`
- [ ] unified time source для `started_at` / `finished_at`
- [ ] config/YAML для non-secret настроек
- [ ] `NormalizedCve` вместо `dict`
- [ ] `NvdNormalizer` class
- [ ] bulk upsert optimization
- [ ] custom exception handler
- [ ] exact months через `relativedelta`
- [ ] retry/backoff/rate-limit handling улучшить
- [ ] logging вместо `print`
- [ ] убрать debug scripts из `app.tests`
- [ ] ruff/pre-commit/import formatting
- [ ] async client/service — только позже, не сейчас
- [ ] OSV / BDU optional sources
- [ ] frontend optional
