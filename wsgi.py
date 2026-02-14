"""
WSGI entry point для Gunicorn и других серверов
"""
import os
import sys

# Добавляем папку app в sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app import app

if __name__ == "__main__":
    app.run()
