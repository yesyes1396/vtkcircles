"""
Утилиты для управления приложением
"""
import sys
import os

# Добавляем папку в путь
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db
from models import User, Course


def init_database():
    """Инициализация базы данных"""
    with app.app_context():
        print("Создание таблиц БД...")
        db.create_all()
        print("✓ БД инициализирована успешно")


def seed_database():
    """Заполнение БД тестовыми данными"""
    with app.app_context():
        # Проверяем, не существует ли администратор
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("Администратор уже существует, пропускаем создание")
        else:
            from datetime import date
            admin = User(
                username='admin',
                email='admin@example.com',
                first_name='Admin',
                last_name='User',
                birth_date=date(1994, 1, 1),  # 30 лет
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            print("✓ Администратор создан (логин: admin, пароль: admin123)")
        
        # Тестовые кружки
        courses_data = [
            {
                'name': 'Футбол',
                'description': 'Обучение основам футбола, техника удара, тактика игры. Развитие командного взаимодействия и спортивного духа.',
                'category': 'sports',
                'min_age': 7,
                'max_age': 16,
                'max_students': 15,
                'schedule': 'пн, ср, пт 16:00-17:30',
                'instructor': 'Иван Петров',
                'icon': 'futbol'
            },
            {
                'name': 'Плавание',
                'description': 'Обучение различным стилям плавания, закаливание, развитие выносливости. Идеально для детей всех уровней подготовки.',
                'category': 'sports',
                'min_age': 5,
                'max_age': 14,
                'max_students': 12,
                'schedule': 'вт, чт 15:00-16:00',
                'instructor': 'Елена Смирнова',
                'icon': 'water'
            },
            {
                'name': 'Рисование',
                'description': 'Развитие творческих способностей, изучение живописи и графики. Работа с различными материалами и техниками.',
                'category': 'art',
                'min_age': 6,
                'max_age': 18,
                'max_students': 20,
                'schedule': 'сб 10:00-12:00',
                'instructor': 'Анна Соколова',
                'icon': 'palette'
            },
            {
                'name': 'Программирование Python',
                'description': 'Изучение основ программирования на Python, создание простых приложений. Подготовка к более сложным языкам.',
                'category': 'science',
                'min_age': 10,
                'max_age': 18,
                'max_students': 18,
                'schedule': 'ср, сб 17:00-18:30',
                'instructor': 'Михаил Козлов',
                'icon': 'code'
            },
            {
                'name': 'Фортепиано',
                'description': 'Индивидуальные занятия по фортепиано для всех уровней. От начинающих до продвинутых музыкантов.',
                'category': 'music',
                'min_age': 6,
                'max_age': 18,
                'max_students': 10,
                'schedule': 'по расписанию',
                'instructor': 'Наталья Волкова',
                'icon': 'music'
            },
            {
                'name': 'Каратэ',
                'description': 'Обучение каратэ, развитие дисциплины и боевых навыков. Подготовка к сдаче поясов.',
                'category': 'sports',
                'min_age': 8,
                'max_age': 17,
                'max_students': 16,
                'schedule': 'пн, пт 18:00-19:30',
                'instructor': 'Виктор Романов',
                'icon': 'dumbbell'
            },
            {
                'name': 'Танцы (Хип-хоп)',
                'description': 'Изучение современных танцевальных стилей, подготовка к выступлениям. Развитие чувства ритма и координации.',
                'category': 'art',
                'min_age': 7,
                'max_age': 16,
                'max_students': 20,
                'schedule': 'вт, чт 17:00-18:30',
                'instructor': 'Ксения Морозова',
                'icon': 'music'
            },
            {
                'name': 'Робототехника',
                'description': 'Конструирование и программирование роботов на базе популярных платформ. Подготовка к робототехническим соревнованиям.',
                'category': 'science',
                'min_age': 9,
                'max_age': 16,
                'max_students': 14,
                'schedule': 'сб 14:00-16:00',
                'instructor': 'Дмитрий Королев',
                'icon': 'code'
            },
        ]
        
        created_count = 0
        for course_data in courses_data:
            if not Course.query.filter_by(name=course_data['name']).first():
                course = Course(**course_data)
                db.session.add(course)
                created_count += 1
        
        db.session.commit()
        print(f"✓ Создано {created_count} кружков")


def reset_database():
    """Полная очистка и пересоздание БД"""
    with app.app_context():
        print("⚠️  Удаление всех таблиц...")
        db.drop_all()
        print("✓ Таблицы удалены")
        
        print("Создание таблиц...")
        db.create_all()
        print("✓ Таблицы созданы")
        
        print("Добавление тестовых данных...")
        seed_database()


def list_users():
    """Вывести список всех пользователей"""
    with app.app_context():
        users = User.query.all()
        if not users:
            print("Пользователей не найдено")
            return
        
        print(f"\n{'ID':<5} {'Username':<20} {'Email':<25} {'Admin':<10}")
        print("-" * 70)
        for user in users:
            admin_status = "✓ Да" if user.is_admin else "✗ Нет"
            print(f"{user.id:<5} {user.username:<20} {user.email:<25} {admin_status:<10}")


def list_courses():
    """Вывести список всех кружков"""
    with app.app_context():
        courses = Course.query.all()
        if not courses:
            print("Кружков не найдено")
            return
        
        print(f"\n{'ID':<5} {'Name':<25} {'Category':<15} {'Enrolled':<12} {'Status':<10}")
        print("-" * 80)
        for course in courses:
            status = "FULL" if course.is_full else "FREE"
            enrolled = f"{course.enrollment_count}/{course.max_students}"
            print(f"{course.id:<5} {course.name:<25} {course.category:<15} {enrolled:<12} {status:<10}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Утилиты для управления приложением')
    subparsers = parser.add_subparsers(dest='command', help='Команда')
    
    subparsers.add_parser('init', help='Инициализировать БД')
    subparsers.add_parser('seed', help='Заполнить БД тестовыми данными')
    subparsers.add_parser('reset', help='Полностью пересоздать БД')
    subparsers.add_parser('users', help='Вывести список пользователей')
    subparsers.add_parser('courses', help='Вывести список кружков')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        init_database()
    elif args.command == 'seed':
        seed_database()
    elif args.command == 'reset':
        reset_database()
    elif args.command == 'users':
        list_users()
    elif args.command == 'courses':
        list_courses()
    else:
        parser.print_help()
