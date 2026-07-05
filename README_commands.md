# Локальный запуск

## Создать venv

#### macos/linux

```
python3 -m venv venv
```

#### windows

```
python -m venv venv
```

---

## Активировать venv

#### macos/linux

```
source venv/bin/activate
```

#### windows

```
venv/scripts/activate
```

---

## Обновить pip, setuptools

#### macos/linux/windows

```
python -m pip install --upgrade pip setuptools wheel
```

---

## Установить проект с dev-зависимостями

### macos/linux/windows

```
pip install -e ".[dev]"
```

---

## Скопировать .env.example в .env

### macos/linux

```
cp .env.example .env
```

### windows

```
copy .env.example .env
```

---

## Миграции бд

### macos/linux/windows - применить миграции

```
alembic upgrade head
```

### macos/linux/windows - создать новую миграцию

```
alembic revision --autogenerate -m "message"
```

---

## Запуск проекта

### macos/linux/windows

```
uvicorn app.main:app --reload
```

url - http://localhost:8000/docs
---

## Тесты

### macos/linux/windows

```
pytest
```

---

# Запуск через Docker

### Последовательность запуска

```
1. поднять контейнеры
2. применить миграции
3. открыть Swagger
4. остановить контейнеры
```

### macos/linux/windows

```
docker compose up --build
docker compose exec backend alembic upgrade head
http://localhost:8000/docs
docker compose down
```

---