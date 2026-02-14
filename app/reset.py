import os
from app import app
from models import db, User

def reset_admin_password():
    # Создаем контекст приложения, чтобы Flask "увидел" базу данных
    with app.app_context():
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        # Ищем пользователя admin
        user = User.query.filter_by(username='admin').first()
        
        if user:
            print(f"Пользователь {user.username} найден. Устанавливаю новый пароль...")
            user.set_password(admin_password) # Устанавливаем пароль
            db.session.commit()
            print(f"Пароль успешно изменен на: {admin_password}")
        else:
            print("Пользователь 'admin' не найден. Создаю нового...")
            # Создаем админа, если его нет (по аналогии с seed_db)
            new_admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            new_admin.set_password(admin_password)
            db.session.add(new_admin)
            db.session.commit()
            print(f"Админ создан. Логин: admin, Пароль: {admin_password}")

if __name__ == '__main__':
    reset_admin_password()