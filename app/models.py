from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date

db = SQLAlchemy()

# Таблица связи многие-ко-многим для пользователей и кружков
enrollment = db.Table(
    'enrollment',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('course_id', db.Integer, db.ForeignKey('course.id'), primary_key=True),
    db.Column('enrollment_date', db.DateTime, default=datetime.utcnow)
)

class User(UserMixin, db.Model):
    """Модель пользователя"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    birth_date = db.Column(db.Date)  # Дата рождения
    avatar = db.Column(db.String(255))  # Путь к аватару
    phone = db.Column(db.String(20))  # Номер телефона (для админов кружков)
    contact_document = db.Column(db.String(255))  # Путь к документу/фото (для админов кружков)
    is_admin = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='student')  # 'student' или 'circle_admin'
    is_verified = db.Column(db.Boolean, default=False)  # Верификация email
    is_approved = db.Column(db.Boolean, default=False)  # Для администраторов кружков требуется одобрение
    is_blocked = db.Column(db.Boolean, default=False)  # Блокировка пользователя
    verification_token = db.Column(db.String(255))  # Токен верификации email
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связь с кружками
    courses = db.relationship('Course', secondary=enrollment, backref=db.backref('students', lazy='dynamic'))
    
    @property
    def age(self):
        """Автоматический расчет возраста по дате рождения"""
        if not self.birth_date:
            return None
        today = date.today()
        return today.year - self.birth_date.year - ((today.month, today.day) < (self.birth_date.month, self.birth_date.day))
    
    @property
    def initials(self):
        """Первые буквы ФИО для заглушки аватара"""
        parts = []
        if self.first_name:
            parts.append(self.first_name[0].upper())
        if self.last_name:
            parts.append(self.last_name[0].upper())
        if not parts and self.username:
            parts.append(self.username[0].upper())
        return ''.join(parts[:2]) or '?'

    def set_password(self, password):
        """Хеширование пароля"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Проверка пароля"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Course(db.Model):
    """Модель кружка/секции"""
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(255))  # Путь к картинке курса
    name = db.Column(db.String(120), nullable=False, index=True)
    description = db.Column(db.Text)
    category = db.Column(db.String(80), nullable=False)  # sports, art, science, music, etc.
    min_age = db.Column(db.Integer, default=6)
    max_age = db.Column(db.Integer, default=18)
    max_students = db.Column(db.Integer, default=20)
    schedule = db.Column(db.String(200))  # e.g., "пн, ср, пт 15:00-16:30"
    instructor = db.Column(db.String(120))
    address = db.Column(db.String(255))  # Адрес проведения
    phone = db.Column(db.String(20))  # Номер телефона
    icon = db.Column(db.String(50), default='dumbbell')  # FontAwesome icon name
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Связь с пользователями (определена выше через enrollment)
    
    @property
    def available_slots(self):
        """Количество доступных мест"""
        return max(0, self.max_students - self.students.count())
    
    @property
    def is_full(self):
        """Заполнен ли кружок"""
        return self.students.count() >= self.max_students
    
    @property
    def enrollment_count(self):
        """Количество записанных студентов"""
        return self.students.count()
    
    @property
    def avg_rating(self):
        """Средний рейтинг курса"""
        all_reviews = self.reviews.all() if hasattr(self.reviews, 'all') else list(self.reviews)
        if not all_reviews:
            return 0
        return round(sum(r.rating for r in all_reviews) / len(all_reviews), 1)

    def __repr__(self):
        return f'<Course {self.name}>'


class Review(db.Model):
    """Модель отзыва о кружке/секции"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('reviews', lazy='dynamic'))
    course = db.relationship('Course', backref=db.backref('reviews', lazy='dynamic'))

    def __repr__(self):
        return f'<Review {self.id} by {self.user_id} for course {self.course_id}>'
