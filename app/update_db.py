#!/usr/bin/env python
"""Скрипт для обновления БД с новой моделью Complaint"""

import os
import sys

# Добавляем папку app в путь
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db

if __name__ == '__main__':
    with app.app_context():
        print("Создание таблиц БД...")
        db.create_all()
        print("✓ БД обновлена успешно!")
        print("✓ Таблица Complaint создана")
