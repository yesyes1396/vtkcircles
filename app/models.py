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
    hide_courses = db.Column(db.Boolean, default=False)  # Скрыть записи от публичного профиля
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
    min_age = db.Column(db.Integer, default=14)
    max_age = db.Column(db.Integer, default=22)
    max_students = db.Column(db.Integer, default=20)
    schedule = db.Column(db.String(200))  # e.g., "пн, ср, пт 15:00-16:30"
    instructor = db.Column(db.String(120))
    address = db.Column(db.String(255))  # Адрес проведения
    phone = db.Column(db.String(20))  # Номер телефона
    icon = db.Column(db.String(50), default='dumbbell')  # FontAwesome icon name
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Кто создал (главный админ в админке)
    
    # Связь с пользователями (определена выше через enrollment)
    created_by = db.relationship('User', backref=db.backref('created_courses', lazy='dynamic'), foreign_keys=[created_by_id])
    
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


class ReviewVote(db.Model):
    """Лайк / дизлайк отзыва"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    is_like = db.Column(db.Boolean, nullable=False)  # True = полезно, False = не полезно
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('review_votes', lazy='dynamic'))
    review = db.relationship('Review', backref=db.backref('votes', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (db.UniqueConstraint('user_id', 'review_id', name='uq_user_review_vote'),)

    def __repr__(self):
        return f'<ReviewVote user={self.user_id} review={self.review_id} like={self.is_like}>'


class EnrollmentRequest(db.Model):
    """Заявка на запись в кружок (требует одобрения админа кружка)"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

    user = db.relationship('User', backref=db.backref('enrollment_requests', lazy='dynamic'))
    course = db.relationship('Course', backref=db.backref('enrollment_requests', lazy='dynamic'))

    def __repr__(self):
        return f'<EnrollmentRequest {self.id} user={self.user_id} course={self.course_id} status={self.status}>'


class Notification(db.Model):
    """Уведомление пользователя (инбокс)"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kind = db.Column(db.String(50), nullable=False)  # enrollment_pending, enrollment_approved, enrollment_rejected, review_vote, new_application, new_review
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    link_url = db.Column(db.String(500))  # Куда перейти по клику
    read_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic', order_by='Notification.created_at.desc()'))

    def __repr__(self):
        return f'<Notification {self.id} user={self.user_id} kind={self.kind}>'


class Complaint(db.Model):
    """Модель жалобы на кружок"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')  # open, in_review, resolved, closed
    admin_response = db.Column(db.Text)  # Ответ администратора
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    responded_at = db.Column(db.DateTime)  # Когда был дан ответ

    user = db.relationship('User', backref=db.backref('complaints', lazy='dynamic'))
    course = db.relationship('Course', backref=db.backref('complaints', lazy='dynamic'))

    def __repr__(self):
        return f'<Complaint {self.id} by {self.user_id} for course {self.course_id}>'
