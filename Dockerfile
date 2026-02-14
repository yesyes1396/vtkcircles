# Используем официальный Python образ
FROM python:3.10-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем requirements.txt
COPY requirements.txt .

# Устанавливаем зависимости Python
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY . .

# Устанавливаем переменные окружения
ENV FLASK_APP=app/app.py
ENV PYTHONUNBUFFERED=1

# Инициализируем БД из корня проекта (app — пакет)
RUN python -c "from app.app import app; from app.models import db; app.app_context().push(); db.create_all()"

# Koyeb по умолчанию проверяет порт 8000
EXPOSE 8000

# Запускаем приложение (PORT задаётся Koyeb, по умолчанию 8000)
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 4 app.app:app"]
