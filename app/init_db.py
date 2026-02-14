#!/usr/bin/env python3
import os
import sys
from app import app, db

def init_db():
    """Инициализация базы данных с удалением старой"""
    
    # Создаём контекст приложения
    with app.app_context():
        # Удаляем старые таблицы
        try:
            db.drop_all()
            print("✓ Старые таблицы удалены")
        except Exception as e:
            print(f"⚠ Ошибка при удалении таблиц: {e}")
        
        # Создаём все таблицы
        db.create_all()
        print("✓ База данных инициализирована успешно")
        
        # Импортируем User для создания админа
        from models import User
        
        # Создаём админа
        admin = User(
            username='admin',
            email='admin@example.com',
            first_name='Админ',
            last_name='Системы',
            is_admin=True,
            is_verified=True
        )
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        admin.set_password(admin_password)
        
        db.session.add(admin)
        db.session.commit()
        print(f"✓ Администратор создан: admin / {admin_password}")
        
    return True

if __name__ == '__main__':
    success = init_db()
    sys.exit(0 if success else 1)
