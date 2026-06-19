Table cve_records {
    id uuid - идентификатор таблицы
    cve_id str unique - идентификатор cve (уязвимости) [АП-01 и СД-04]
    source_identifier str - источник уязвимости [АП-01]
    published_at datetime - дата публикации уязвимости [АП-02]
    last_modified_at datetime - последнее обновления уязвимости [СД-02]
    vuln_status str - статус NVD для понимания состояния записи в базе VND [АП-01]
    description str - описание уязвимости для подробного просмотра [АП-01 и ФЕ-02]
    cvss_base_score float nullable - оценка для подробного просмотра и статистики [АП-03]
    cvss_base_severity str - урвоень критичности для фильтрации [АП-02 и АП-03]
    cvss_vector str nullable - нужен для подробного просмотра
    created_at datetime  - дата создания записи в нашей бд
    updated_at datetime - дата обновления записи из нашей бд [СД-02]
    raw_json jsonb - сырой json для референса [АП-01]
    }

Table runs_sync {
    id int - идентификатор таблицы
    source str - когда будет расширяться то нужно указывать путь откуда пришла уязвимость [СД-05]
    status str - статус синхронизации [СД-03]
    added_count int - количество добавленных уязвимостей [СД-03]
    updated_count int - количество обновленных уязвимостей [СД-03]
    error_message str - сообщение ошибки [СД-03]
    started_at datetime - время старта синхронизации [СД-03]
    finished_at datetime nullable - время финиша синхронизации [СД-03]
    }