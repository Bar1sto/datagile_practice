# CVE Tracker

Backend-сервис для загрузки CVE, хранения в PostgreSQL и поиска уязвимостей через REST API

## Стек

- Python 3.11+
- FastAPI
- PostgreSQL
- SQLAlchemy 2.0
- Alembic
- APScheduler
- httpx
- pytest
- Docker / docker-compose

## Что реализовано

- Загрузка CVE из NVD API
- Первичная/периодическая синхронизация
- Ручной запуск синхронизации через API
- Таблица `sync_runs` со статусами запусков
- Upsert CVE без дублей при повторной синхронизации
- Хранение affected products: vendor, product, version
- Получение CVE по `cve_id`
- Список CVE с пагинацией
- Фильтры по severity, date range, vendor, product
- Endpoint статистики
- Единая структура ошибок
- Swagger UI
- Unit-тесты для NVD normalizer
- Docker-конфигурация подготовлена

## API endpoints

- `GET /health`
- `GET /cve`
- `GET /cve/{cve_id}`
- `GET /stats`
- `POST /sync-runs/nvd/recent`

## Структура проекта

```
app/ - корень программы
  main.py - основной файл, точка входа

  clients/ - клиент для работы с внешним API и сервисами
    nvd.py
  
  core/ - папка настроек, конфиг из .env
    config.py

  db/ - папка работа с бд, сессии, алхимия, управление подключениями к бд (ЖЦ)
    database.py

  models/ - папка моделей, орм модели таблицы бд
    cve.py
    sync_run.py

  schemas/ - пайдантик схемы ответа АПИ
    cve.py
    

  api/ - папка роутеров
    health.py
    cve.py

  repositories/ - папка sql запросов, получение сохранение cve, поиск по айди
    cve.py

  services/ - папка бизнес логики, что делать с све, как обрабатывать данные
    cve.py

  normalizers/ - папка преобразования vnd json к внутренним данным
    nvd.py

  /docs - папка с md документами с разбором тз, бд и первым получением json от vnd
```

## ER-диаграмма

![docs](docs/er-diagramm.png)
