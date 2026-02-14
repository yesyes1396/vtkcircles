# Система записи на кружки и секции

Веб-приложение для управления записью на кружки и секции с поддержкой администраторской панели.

## Особенности

- ✅ **Каталог кружков** - красивый интерфейс с фильтрацией по возрасту и категориям
- ✅ **Авторизация** - система регистрации и входа для пользователей
- ✅ **Личный кабинет** - просмотр и управление записями пользователя
- ✅ **Панель администратора** - управление кружками и просмотр записавшихся
- ✅ **Проверка лимитов** - блокировка записи при заполнении кружка
- ✅ **Адаптивный дизайн** - корректно отображается на всех устройствах
- ✅ **Bootstrap 5 & FontAwesome** - современный и красивый интерфейс

## Технологический стек

### Backend
- **Python 3.10+**
- **Flask** - веб-фреймворк
- **Flask-SQLAlchemy** - ORM для работы с БД
- **Flask-Login** - управление сессиями пользователей
- **Werkzeug** - безопасная обработка паролей

### Frontend
- **HTML5** - разметка
- **Jinja2** - шаблонизация
- **Bootstrap 5** - стили и компоненты (CDN)
- **FontAwesome 6+** - иконки (CDN)

### Database
- **SQLite** - для разработки (встроенная БД)
- **PostgreSQL** - для продакшена (опционально)

### DevOps
- **Docker** - контейнеризация
- **Docker Compose** - оркестрация контейнеров

## Установка и запуск

### 1. Локальная разработка (без Docker)

```bash
# Клонируем репозиторий
git clone <repo-url>
cd courses

# Создаем виртуальное окружение
python -m venv venv

# Активируем виртуальное окружение
# На Windows:
venv\Scripts\activate
# На macOS/Linux:
source venv/bin/activate

# Устанавливаем зависимости
pip install -r requirements.txt

# Инициализируем БД и заполняем тестовыми данными
cd app
python -c "from app import app, db; app.app_context().push(); db.create_all()"
python app.py init-db
python app.py seed-db

# Запускаем приложение
python app.py runserver
```

Приложение будет доступно по адресу: **http://localhost:5000**

### 2. Запуск с Docker Compose

```bash
# Переходим в директорию проекта
cd courses

# Запускаем контейнеры
docker-compose up -d

# Проверяем логи
docker-compose logs -f web

# Останавливаем контейнеры
docker-compose down
```

Приложение будет доступно по адресу: **http://localhost:5000**

## Структура проекта

```
courses/
├── app/
│   ├── templates/
│   │   ├── base.html              # Базовый шаблон
│   │   ├── index.html             # Главная страница
│   │   ├── course_detail.html     # Детали кружка
│   │   ├── register.html          # Регистрация
│   │   ├── login.html             # Логин
│   │   ├── profile.html           # Личный кабинет
│   │   └── admin/
│   │       ├── dashboard.html     # Панель администратора
│   │       ├── add_course.html    # Добавление кружка
│   │       ├── edit_course.html   # Редактирование кружка
│   │       └── course_enrollments.html  # Список записавшихся
│   ├── static/                    # Статические файлы (CSS, JS, изображения)
│   ├── app.py                     # Основное приложение Flask
│   └── models.py                  # Модели БД (User, Course)
├── requirements.txt               # Зависимости Python
├── Dockerfile                     # Конфигурация Docker
├── docker-compose.yml             # Конфигурация Docker Compose
├── .env                          # Переменные окружения (локально)
├── .gitignore                    # Git ignore файл
└── README.md                     # Этот файл
```

## Модели БД

### User (Пользователь)
```python
- id: Integer (PRIMARY KEY)
- username: String (UNIQUE, NOT NULL)
- email: String (UNIQUE, NOT NULL)
- password_hash: String (NOT NULL)
- first_name: String
- last_name: String
- age: Integer
- is_admin: Boolean (default: False)
- created_at: DateTime
- courses: Relationship (Many-to-Many с Course)
```

### Course (Кружок/Секция)
```python
- id: Integer (PRIMARY KEY)
- name: String (NOT NULL)
- description: Text
- category: String (sports, art, science, music, etc.)
- min_age: Integer (default: 6)
- max_age: Integer (default: 18)
- max_students: Integer (default: 20)
- schedule: String (расписание)
- instructor: String (преподаватель)
- icon: String (FontAwesome иконка)
- created_at: DateTime
- updated_at: DateTime
- students: Relationship (Many-to-Many с User)
```

### Enrollment (Запись на кружок)
```python
- user_id: Integer (FOREIGN KEY)
- course_id: Integer (FOREIGN KEY)
- enrollment_date: DateTime
```

## Основные функции

### 1. Главная страница (/)
- Список всех кружков в виде карточек
- Фильтрация по категориям
- Поиск по названию
- Фильтрация по возрасту
- Пагинация (12 кружков на странице)

### 2. Детальная страница кружка (/course/<id>)
- Полная информация о кружке
- Расписание и преподаватель
- Индикатор заполнения мест
- Кнопка записи/отписки
- Проверка возраста

### 3. Авторизация
- **Регистрация (/register)**
  - Создание нового аккаунта
  - Указание возраста для автоматического фильтра
  - Валидация пароля

- **Логин (/login)**
  - Вход по имени пользователя и пароли
  - Опция "Запомнить меня"
  - Демо учетные данные (admin/admin123)

### 4. Личный кабинет (/profile)
- Список активных записей
- Информация профиля
- Возможность отписаться от кружка
- Статистика

### 5. Панель администратора (/admin)
- **Обязательно**: is_admin=True в БД
- Статистика по кружкам и пользователям
- Управление кружками:
  - Добавление (/admin/course/add)
  - Редактирование (/admin/course/<id>/edit)
  - Удаление (/admin/course/<id>/delete)
- Просмотр записавшихся студентов (/admin/course/<id>/enrollments)

## CLI Команды

```bash
# Инициализация БД
python app.py init-db

# Заполнение тестовыми данными
python app.py seed-db
```

## Демонстрационные данные

При запуске `seed-db` создаются:

**Администратор:**
- Логин: `admin`
- Пароль: `admin123`

**Тестовые кружки:**
- Футбол (спорт, 7-16 лет)
- Плавание (спорт, 5-14 лет)
- Рисование (искусство, 6-18 лет)
- Программирование Python (наука, 10-18 лет)
- Фортепиано (музыка, 6-18 лет)
- Каратэ (спорт, 8-17 лет)
- Танцы (искусство, 7-16 лет)
- Робототехника (наука, 9-16 лет)

## Безопасность

- ✅ Пароли хешируются с использованием Werkzeug
- ✅ CSRF защита токенами для всех POST-форм
- ✅ SQL инъекции защита через SQLAlchemy ORM
- ✅ Проверка прав доступа для админ-функций
- ✅ Валидация входных данных

## Настройка для продакшена

1. **Измените SECRET_KEY в .env**
```bash
SECRET_KEY=your-very-long-random-secret-key-here
```

2. **Переключитесь на PostgreSQL**
   - Раскомментируйте секцию `db` в docker-compose.yml
   - Обновите DATABASE_URL в .env

3. **Включите HTTPS**
   - Используйте Nginx как reverse proxy
   - Настройте SSL сертификаты

4. **Установите переменные окружения**
```bash
export FLASK_ENV=production
export SECRET_KEY=your-secret-key
export ADMIN_PASSWORD=change-this-admin-password
export APP_NAME="ВТК г. Кокшетау"
```

## Расширение функционала

Возможные улучшения:

- [ ] Email подтверждение при регистрации
- [ ] Восстановление пароля
- [ ] Рейтинги и отзывы кружков
- [ ] Система оплаты
- [ ] Уведомления об изменениях расписания
- [ ] Экспорт списков в PDF/Excel
- [ ] Интеграция с Google Calendar
- [ ] Мобильное приложение
- [ ] Видеоконтент для кружков
- [ ] Система квестов и достижений

## Возможные проблемы

### Проблема: "Address already in use"
```bash
# Измените порт в docker-compose.yml
ports:
  - "8000:5000"  # или другой свободный порт
```

### Проблема: БД не инициализируется
```bash
# Удалите старые контейнеры
docker-compose down -v

# Пересоздайте контейнеры
docker-compose up --build
```

### Проблема: Статические файлы не загружаются
```bash
# Убедитесь что папка static существует
mkdir -p app/static
```

## Поддержка

Если возникли вопросы или проблемы, свяжитесь с разработчиком.

## Лицензия

MIT License

## Автор

Разработано как учебный проект для изучения Flask и веб-разработки.

---

**Версия:** 1.0.0  
**Дата обновления:** 28 января 2026 г.
