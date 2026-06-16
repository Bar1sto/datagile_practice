# Цель
    сервис собирает, хранит и отображает данные об уязвимостях из открытой базы NVD. сервис обеспечивает автоматическую синхронизацию раз в сутки и предоставляет REST API и веб для поиска и просмотра уязвимостей

# МВП
    реализация всех must have:
    - получать NVD, сохранять в постгре,=
    - делать миграции через алембик
    - три эндпоинта:
     get /cve/{cve_id},
     get /cve,
     get /stats,
    - сохранение логов синхронизации, 
    - запуск через докер компос
    - покрытие тестами
    - редми

# Что проходит через систему
    NVD API

# Черновик бд
    Table cve_records {
    id uuid
    cve_id str unique
    source_identifier str 
    published_at datetime
    last_modified_at datetime
    vuln_status str
    description str
    cvss_base_score float nullable
    cvss_base_severity str
    cvss_vector str nullable
    created_at datetime 
    updated_at datetime
    raw_json jsonb
    }

    Table runs_sync {
    id int
    source str
    status str
    added_count int
    updated_count int 
    error_message str
    started_at datetime
    finished_at datetime nullable
    }

# Апишки
    get /cve/{cve_id}
    get /cve
    get /stats

# Процесс синхронизации
    При первом запуске, когда бд пустая, делается запрос за последние 12 месяцев, после чего делается синхронизация раз в сутки

