#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, 'app')

from app import app, db
from models import User

with app.app_context():
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    user = User.query.filter_by(username='admin').first()
    
    if user:
        print(f"✓ Найден пользователь: {user.username}")
        user.set_password(admin_password)
        db.session.commit()
        print(f"✓ Пароль установлен на: {admin_password}")
        print(f"✓ Email: {user.email}")
        print(f"✓ Администратор: {user.is_admin}")
    else:
        print("✗ Администратор не найден!")
        # Создаём нового админа
        new_admin = User(
            username='admin',
            email='admin@example.com',
            first_name='Админ',
            last_name='Системы',
            is_admin=True,
            is_verified=True
        )
        new_admin.set_password(admin_password)
        db.session.add(new_admin)
        db.session.commit()
        print("✓ Администратор создан")
        print("✓ Логин: admin")
        print(f"✓ Пароль: {admin_password}")
