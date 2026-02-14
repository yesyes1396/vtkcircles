import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
try:
    from .models import db, User, Course, enrollment, Review, ReviewVote, Complaint, EnrollmentRequest
except ImportError:
    from models import db, User, Course, enrollment, Review, ReviewVote, Complaint, EnrollmentRequest
from datetime import datetime, timedelta, date
from functools import wraps
from werkzeug.utils import secure_filename
import secrets
import re
from collections import defaultdict
from urllib.parse import urlparse, urljoin
import uuid
import shutil

app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///courses.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), '..', 'uploads')
_APP_NAME_DEFAULT = '\u0412\u0422\u041a \u0433. \u041a\u043e\u043a\u0448\u0435\u0442\u0430\u0443'  # ВТК г. Кокшетау
_env_app_name = os.environ.get('APP_NAME', '').strip()
# Discard ASCII placeholders and garbled values – always use proper Russian default
if not _env_app_name or all(ord(ch) < 128 for ch in _env_app_name):
    _env_app_name = ''
app.config['APP_NAME'] = _env_app_name or _APP_NAME_DEFAULT

# Создание папки для загрузок если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'courses'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'courses', 'gallery'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'admin_documents'), exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    """Проверка расширения файла"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Инициализация расширений
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== Проверка блокировки перед каждым запросом ====================
@app.before_request
def check_if_user_blocked():
    """Проверка: если пользователь заблокирован, разорвать его сессию"""
    if current_user.is_authenticated:
        # Перезагружаем актуальные данные из БД
        user = User.query.get(current_user.id)
        if user and user.is_blocked:
            logout_user()
            flash('Ваш аккаунт был заблокирован администратором.', 'danger')
            return redirect(url_for('login'))

# Декоратор для проверки прав администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('У вас нет прав доступа.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для проверки прав администратора кружка
def circle_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'circle_admin':
            flash('У вас нет прав доступа. Требуется быть администратором кружка.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== Вспомогательные функции для загрузок ====================
def delete_file_if_exists(relative_path):
    """Удалить файл с диска по относительному пути (uploads/...).  Safe no-op if missing."""
    if not relative_path:
        return
    abs_path = os.path.join(os.path.dirname(__file__), '..', relative_path)
    abs_path = os.path.normpath(abs_path)
    if os.path.isfile(abs_path):
        try:
            os.remove(abs_path)
        except OSError:
            pass


def save_upload_file(file, folder):
    """Сохранение загруженного файла"""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Добавляем временную метку для уникальности
        filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
        file.save(filepath)
        return f"uploads/{folder}/{filename}"
    return None


def save_course_gallery_images(course_id, files):
    """Сохранение нескольких изображений галереи курса"""
    gallery_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'courses', 'gallery', str(course_id))
    os.makedirs(gallery_dir, exist_ok=True)

    saved_paths = []
    for file in files:
        if not file or not file.filename:
            continue
        if not allowed_file(file.filename):
            continue
        filename = secure_filename(file.filename)
        filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(gallery_dir, filename)
        file.save(filepath)
        saved_paths.append(f"uploads/courses/gallery/{course_id}/{filename}")
    return saved_paths


def get_course_gallery_images(course_id):
    """Получить список изображений галереи курса"""
    gallery_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'courses', 'gallery', str(course_id))
    if not os.path.isdir(gallery_dir):
        return []
    files = sorted(os.listdir(gallery_dir))
    return [f"uploads/courses/gallery/{course_id}/{name}" for name in files if allowed_file(name)]


def ensure_default_admin():
    """Гарантировать наличие главного администратора"""
    default_password = os.environ.get('ADMIN_PASSWORD', '1396!YtUhSgBlJhS')
    admin = User.query.filter_by(username='mainadmin').first()
    if admin:
        if not admin.is_admin:
            admin.is_admin = True
        admin.set_password(default_password)
        db.session.commit()
        return

    admin = User(
        username='mainadmin',
        email='mainadmin@vtk.local',
        is_admin=True,
        is_verified=True,
        is_approved=True
    )
    admin.set_password(default_password)
    db.session.add(admin)
    db.session.commit()

# ==================== Функции безопасности ====================

# Rate limiting для защиты от брутфорса
request_history = defaultdict(list)

def is_rate_limited(ip, max_requests=5, window=300):
    """Проверка rate limiting (5 запросов за 5 минут)"""
    now = datetime.now()
    cutoff = now - timedelta(seconds=window)
    
    # Очистить старые запросы
    request_history[ip] = [req_time for req_time in request_history[ip] if req_time > cutoff]
    
    if len(request_history[ip]) >= max_requests:
        return True
    
    request_history[ip].append(now)
    return False

def generate_verification_token():
    """Генерация токена верификации"""
    return secrets.token_urlsafe(32)


def generate_csrf_token():
    """Генерация CSRF-токена для защиты POST-форм"""
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.context_processor
def inject_template_globals():
    """Глобальные переменные для шаблонов"""
    return {
        'csrf_token': generate_csrf_token,
        'app_name': app.config.get('APP_NAME', 'ВТК г. Кокшетау')
    }


@app.before_request
def csrf_protect():
    """Проверка CSRF-токена для небезопасных HTTP-методов"""
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None

    # Разрешаем только запросы с валидным токеном
    session_token = session.get('_csrf_token')
    request_token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')

    if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
        flash('Сессия формы устарела. Пожалуйста, повторите действие.', 'danger')
        return redirect(request.referrer or url_for('index'))
    return None


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Отдача файлов из папки uploads"""
    uploads_root = os.path.abspath(app.config['UPLOAD_FOLDER'])
    normalized_path = os.path.normpath(filename)
    full_path = os.path.abspath(os.path.join(uploads_root, normalized_path))

    if not full_path.startswith(uploads_root):
        return redirect(url_for('index'))
    if not os.path.exists(full_path):
        return redirect(url_for('index'))

    directory = os.path.dirname(full_path)
    basename = os.path.basename(full_path)
    return send_from_directory(directory, basename)

def validate_password_strength(password):
    """Валидация пароля на устойчивость"""
    if len(password) < 6:
        return False, "Пароль должен быть не менее 6 символов"
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[a-zа-яё]', password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать хотя бы одну цифру"
    if not re.search(r'[^A-Za-zА-Яа-яЁё0-9]', password):
        return False, "Пароль должен содержать хотя бы один спецсимвол (!@#$%...)"
    return True, "OK"

def sanitize_input(text):
    """Санитизация пользовательского ввода"""
    if not text:
        return ""
    # Удалить опасные символы
    text = text.strip()
    # Удалить HTML теги
    text = re.sub(r'<[^>]+>', '', text)
    return text

# ==================== Главная страница ====================
@app.route('/')
def index():
    """Главная страница со списком кружков"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    min_age = request.args.get('min_age', '', type=str)
    max_age = request.args.get('max_age', '', type=str)
    category = request.args.get('category', '').strip()
    
    query = Course.query
    
    # Фильтрация по поиску
    if search:
        query = query.filter(
            (Course.name.ilike(f'%{search}%')) |
            (Course.description.ilike(f'%{search}%'))
        )
    
    # Фильтрация по возрасту
    if min_age:
        try:
            age = int(min_age)
            query = query.filter(Course.max_age >= age)
        except ValueError:
            pass
    
    if max_age:
        try:
            age = int(max_age)
            query = query.filter(Course.min_age <= age)
        except ValueError:
            pass
    
    # Фильтрация по категории
    if category:
        query = query.filter(Course.category == category)
    
    # Сортировка и пагинация
    courses = query.order_by(Course.created_at.desc()).paginate(page=page, per_page=12)
    
    # Получить все категории для фильтра
    categories = db.session.query(Course.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    
    return render_template(
        'index.html',
        courses=courses,
        categories=categories,
        search=search,
        min_age=min_age,
        max_age=max_age,
        category=category
    )

# ==================== Детальная страница кружка ====================
@app.route('/course/<int:course_id>')
def course_detail(course_id):
    """Детальная страница кружка"""
    course = Course.query.get_or_404(course_id)
    is_enrolled = False
    pending_request = None
    gallery_images = get_course_gallery_images(course.id)
    
    if current_user.is_authenticated:
        is_enrolled = current_user in course.students.all()
        if not is_enrolled:
            pending_request = EnrollmentRequest.query.filter_by(
                user_id=current_user.id, course_id=course_id, status='pending'
            ).first()
    
    reviews = Review.query.filter_by(course_id=course.id).order_by(Review.created_at.desc()).all()
    user_review = None
    can_manage = False
    if current_user.is_authenticated:
        user_review = Review.query.filter_by(course_id=course.id, user_id=current_user.id).first()
        if current_user.is_admin:
            can_manage = True
        elif current_user.user_type == 'circle_admin':
            iname = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
            if course.instructor == iname:
                can_manage = True

    return render_template(
        'course_detail.html',
        course=course,
        is_enrolled=is_enrolled,
        pending_request=pending_request,
        gallery_images=gallery_images,
        reviews=reviews,
        user_review=user_review,
        can_manage=can_manage
    )


# ==================== Отзывы ====================
@app.route('/course/<int:course_id>/review', methods=['POST'])
@login_required
def add_review(course_id):
    """Добавить или обновить отзыв (только для записанных)"""
    course = Course.query.get_or_404(course_id)

    if current_user not in course.students.all():
        flash('Оставлять отзывы могут только записанные на кружок.', 'warning')
        return redirect(url_for('course_detail', course_id=course_id))

    rating = request.form.get('rating', 0, type=int)
    text = sanitize_input(request.form.get('text', ''))

    if rating < 1 or rating > 5:
        flash('Оценка должна быть от 1 до 5.', 'danger')
        return redirect(url_for('course_detail', course_id=course_id))

    existing = Review.query.filter_by(course_id=course_id, user_id=current_user.id).first()
    if existing:
        existing.rating = rating
        existing.text = text
    else:
        review = Review(user_id=current_user.id, course_id=course_id, rating=rating, text=text)
        db.session.add(review)

    db.session.commit()
    flash('Ваш отзыв сохранён!', 'success')
    return redirect(url_for('course_detail', course_id=course_id))


@app.route('/course/<int:course_id>/review/delete', methods=['POST'])
@login_required
def delete_review(course_id):
    """Удалить свой отзыв"""
    review = Review.query.filter_by(course_id=course_id, user_id=current_user.id).first()
    if review:
        db.session.delete(review)
        db.session.commit()
        flash('Отзыв удалён.', 'info')
    return redirect(url_for('course_detail', course_id=course_id))


# ==================== Голосование за отзыв ====================
@app.route('/review/<int:review_id>/vote', methods=['POST'])
@login_required
def vote_review(review_id):
    """Поставить лайк или дизлайк отзыву"""
    review = Review.query.get_or_404(review_id)
    vote_type = request.form.get('vote')  # 'like' or 'dislike'
    if vote_type not in ('like', 'dislike'):
        return redirect(url_for('course_detail', course_id=review.course_id))

    is_like = (vote_type == 'like')
    existing = ReviewVote.query.filter_by(user_id=current_user.id, review_id=review_id).first()

    if existing:
        if existing.is_like == is_like:
            # Повторный клик — убрать голос
            db.session.delete(existing)
        else:
            # Переключить голос
            existing.is_like = is_like
    else:
        db.session.add(ReviewVote(user_id=current_user.id, review_id=review_id, is_like=is_like))

    db.session.commit()
    return redirect(url_for('course_detail', course_id=review.course_id) + '#review-' + str(review_id))


# ==================== Запись на кружок (заявка) ====================
@app.route('/enroll/<int:course_id>', methods=['POST'])
@login_required
def enroll_course(course_id):
    """Подать заявку на запись в кружок (одобряет админ кружка)"""
    course = Course.query.get_or_404(course_id)
    
    # Проверка возраста
    if current_user.age:
        if current_user.age < course.min_age or current_user.age > course.max_age:
            flash(f'Ваш возраст не подходит для этого кружка (требуется {course.min_age}-{course.max_age} лет).', 'warning')
            return redirect(url_for('course_detail', course_id=course_id))
    
    if course.is_full:
        flash('К сожалению, в этом кружке нет свободных мест.', 'warning')
        return redirect(url_for('course_detail', course_id=course_id))
    
    if current_user in course.students.all():
        flash('Вы уже записаны на этот кружок.', 'info')
        return redirect(url_for('course_detail', course_id=course_id))
    
    # Проверка, нет ли уже заявки в ожидании
    existing = EnrollmentRequest.query.filter_by(
        user_id=current_user.id, course_id=course_id, status='pending'
    ).first()
    if existing:
        flash('Ваша заявка уже на рассмотрении.', 'info')
        return redirect(url_for('course_detail', course_id=course_id))
    
    req = EnrollmentRequest(user_id=current_user.id, course_id=course_id)
    db.session.add(req)
    db.session.commit()
    flash('Заявка отправлена! Администратор кружка скоро её рассмотрит.', 'success')
    
    return redirect(url_for('course_detail', course_id=course_id))

# ==================== Отмена заявки ====================
@app.route('/cancel-enrollment/<int:course_id>', methods=['POST'])
@login_required
def cancel_enrollment(course_id):
    """Отменить ожидающую заявку на кружок"""
    req = EnrollmentRequest.query.filter_by(
        user_id=current_user.id, course_id=course_id, status='pending'
    ).first()
    if req:
        db.session.delete(req)
        db.session.commit()
        flash('Заявка отменена.', 'info')
    return redirect(url_for('course_detail', course_id=course_id))

# ==================== Отписка от кружка ====================
@app.route('/unenroll/<int:course_id>', methods=['POST'])
@login_required
def unenroll_course(course_id):
    """Отписать пользователя от кружка"""
    course = Course.query.get_or_404(course_id)
    
    if current_user not in course.students.all():
        flash('Вы не записаны на этот кружок.', 'warning')
        return redirect(url_for('course_detail', course_id=course_id))
    
    current_user.courses.remove(course)
    db.session.commit()
    flash(f'Вы отписались от кружка "{course.name}".', 'info')
    
    return redirect(url_for('course_detail', course_id=course_id))

# ==================== Личный кабинет ====================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Личный кабинет пользователя"""
    if request.method == 'POST':
        # Обновление профиля
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        birth_date_str = request.form.get('birth_date', '').strip()
        phone = request.form.get('phone', '').strip()
        
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.phone = phone
        
        if birth_date_str:
            try:
                current_user.birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Неверный формат даты рождения.', 'danger')
                return redirect(url_for('profile'))
        
        # Загрузка аватара (удаляем старый файл при замене)
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file:
                avatar_path = save_upload_file(file, 'avatars')
                if avatar_path:
                    old_avatar = current_user.avatar
                    current_user.avatar = avatar_path
                    delete_file_if_exists(old_avatar)
                else:
                    flash('Неверный формат файла. Используйте PNG, JPG, GIF или WebP.', 'warning')
        
        db.session.commit()
        flash('Профиль обновлен!', 'success')
        return redirect(url_for('profile'))
    
    user = current_user
    return render_template('profile.html', user=user)

# ==================== Переключение видимости кружков ====================
@app.route('/profile/toggle-courses-visibility', methods=['POST'])
@login_required
def toggle_courses_visibility():
    """Переключить видимость кружков в публичном профиле"""
    current_user.hide_courses = not current_user.hide_courses
    db.session.commit()
    if current_user.hide_courses:
        flash('Ваши записи на кружки теперь скрыты от других.', 'info')
    else:
        flash('Ваши записи на кружки теперь видны в вашем публичном профиле.', 'success')
    return redirect(url_for('profile'))

# ==================== Публичный профиль пользователя ====================
@app.route('/user/<int:user_id>')
def user_public_profile(user_id):
    """Публичный профиль пользователя (доступен всем)"""
    user = User.query.get_or_404(user_id)
    
    # Определить, может ли зритель видеть кружки
    show_courses = False
    if current_user.is_authenticated and current_user.is_admin:
        show_courses = True  # Админ видит всё
    elif current_user.is_authenticated and current_user.id == user.id:
        show_courses = True  # Свой профиль
    elif not user.hide_courses:
        show_courses = True  # Пользователь разрешил показ
    
    courses = list(user.courses) if show_courses else []
    reviews = Review.query.filter_by(user_id=user.id).order_by(Review.created_at.desc()).all() if show_courses else []
    
    return render_template('user_profile.html', user=user, courses=courses, reviews=reviews, show_courses=show_courses)

# ==================== Регистрация ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Rate limiting защита от брутфорса
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            flash('Слишком много попыток регистрации. Попробуйте позже.', 'danger')
            return redirect(url_for('register'))
        
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        first_name = sanitize_input(request.form.get('first_name', ''))
        last_name = sanitize_input(request.form.get('last_name', ''))
        user_type = request.form.get('user_type', 'student').strip()
        birth_date_str = request.form.get('birth_date', '').strip()
        organization = sanitize_input(request.form.get('organization', ''))
        phone = sanitize_input(request.form.get('phone', ''))
        
        # Общая валидация render-helper
        def reg_error(msg):
            flash(msg, 'danger')
            return render_template('register.html',
                username=username, email=email, first_name=first_name,
                last_name=last_name, birth_date=birth_date_str,
                organization=organization, user_type=user_type, phone=phone)

        # Валидация типа пользователя
        if user_type not in ['student', 'circle_admin']:
            return reg_error('Неверный тип пользователя.')
        
        # Валидация имени пользователя
        if not username or len(username) < 3 or len(username) > 80:
            return reg_error('Имя пользователя должно содержать 3-80 символов.')
        
        if not re.match(r'^[a-zA-Z0-9_\-]*$', username):
            return reg_error('Имя пользователя может содержать только буквы, цифры, подчеркивание и тире.')
        
        # Валидация email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return reg_error('Некорректный адрес электронной почты.')
        
        # Имя и фамилия обязательны
        if not first_name or not last_name:
            return reg_error('Имя и фамилия обязательны.')
        
        # Валидация пароля на устойчивость
        password_valid, password_msg = validate_password_strength(password)
        if not password_valid:
            return reg_error(password_msg)
        
        # Парсинг даты рождения (обязательна)
        birth_date = None
        if not birth_date_str:
            return reg_error('Укажите дату рождения.')
        try:
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
            # Рассчитаем возраст
            today = date.today()
            age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
            if age < 14 or age > 22:
                return reg_error(f'Возраст должен быть от 14 до 22 лет (ваш: {age}).')
        except ValueError:
            return reg_error('Неверный формат даты рождения.')
        
        # Валидация контактных данных для администраторов кружков
        if user_type == 'circle_admin':
            if not phone or len(phone) < 10:
                return reg_error('Пожалуйста, укажите корректный номер телефона.')
            
            if 'contact_document' not in request.files or request.files['contact_document'].filename == '':
                return reg_error('Пожалуйста, прикрепите документ или фото.')
        
        # Валидация обязательных полей
        if not username or not email or not password:
            return reg_error('Пожалуйста, заполните все обязательные поля.')
        
        if password != password_confirm:
            return reg_error('Пароли не совпадают.')
        
        # Проверка существования пользователя
        if User.query.filter_by(username=username).first():
            return reg_error('Это имя пользователя уже занято.')
        
        if User.query.filter_by(email=email).first():
            return reg_error('Этот адрес электронной почты уже зарегистрирован.')
        
        # Обработка загрузки документа для администраторов кружков
        contact_document_path = None
        if user_type == 'circle_admin' and 'contact_document' in request.files:
            contact_document = request.files['contact_document']
            if contact_document and allowed_file(contact_document.filename):
                contact_document_path = save_upload_file(contact_document, 'admin_documents')
        
        # Создание пользователя
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            birth_date=birth_date,
            phone=phone,
            contact_document=contact_document_path,
            user_type=user_type,
            is_verified=False,
            is_approved=False if user_type == 'circle_admin' else True,
            verification_token=generate_verification_token()
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        if user_type == 'circle_admin':
            flash('Регистрация успешна! Ваш аккаунт отправлен на модерацию. Вы получите уведомление после проверки.', 'success')
        else:
            flash('Регистрация успешна! Теперь вы можете войти и записаться на кружки.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ==================== Логин ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Вход в систему"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Пожалуйста, заполните все поля.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            flash('Неправильное имя пользователя или пароль.', 'danger')
            return redirect(url_for('login'))
        
        # Проверка: пользователь не заблокирован
        if user.is_blocked:
            flash('Ваш аккаунт был заблокирован администратором.', 'danger')
            return redirect(url_for('login'))
        
        # Проверка: администратор кружка должен быть одобрен
        if user.user_type == 'circle_admin' and not user.is_approved:
            flash('Ваш аккаунт ждет одобрения администратора. Пожалуйста, попробуйте позже.', 'warning')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        
        if next_page and url_has_allowed_host_and_scheme(next_page):
            flash(f'Добро пожаловать, {user.username}!', 'success')
            return redirect(next_page)

        flash(f'Добро пожаловать, {user.username}!', 'success')
        return redirect(url_for('index'))
    
    return render_template('login.html')

# ==================== Выход ====================
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Выход из системы"""
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

# ==================== Панель администратора ====================
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Панель администратора (перенаправление на новый dashboard)"""
    return redirect(url_for('admin_dashboard_main'))

# ==================== Модерация администраторов кружков ====================
@app.route('/admin/approve-circle-admin/<int:user_id>', methods=['POST'])
@admin_required
def approve_circle_admin(user_id):
    """Одобрить администратора кружка"""
    # Защита от изменения себя
    if user_id == current_user.id:
        flash('Вы не можете одобрить самого себя.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.user_type != 'circle_admin':
        flash('Этот пользователь не является администратором кружка.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Защита от одобрения админов системы
    if user.is_admin:
        flash('Этот пользователь уже является администратором системы.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user.is_approved = True
    db.session.commit()
    flash(f'Администратор кружка {user.username} одобрен.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-circle-admin/<int:user_id>', methods=['POST'])
@admin_required
def reject_circle_admin(user_id):
    """Отклонить администратора кружка"""
    # Защита от удаления себя
    if user_id == current_user.id:
        flash('Вы не можете отклонить самого себя.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if user.user_type != 'circle_admin':
        flash('Этот пользователь не является администратором кружка.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Защита от удаления других админов
    if user.is_admin:
        flash('Вы не можете удалять администраторов системы.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f'Аккаунт администратора кружка {user.username} отклонен и удален.', 'success')
    return redirect(url_for('admin_dashboard'))

# ==================== Управление пользователями (блокировка/удаление) ====================
@app.route('/admin/user/<int:user_id>/block', methods=['POST'])
@admin_required
def admin_block_user(user_id):
    """Заблокировать пользователя"""
    # Защита от блокировки себя
    if user_id == current_user.id:
        flash('Вы не можете заблокировать самого себя.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Защита от блокировки других админов
    if user.is_admin:
        flash('Вы не можете блокировать администраторов системы.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user.is_blocked = True
    db.session.commit()
    
    # Сессия пользователя будет прервана при следующем запросе через before_request хук
    # Если пользователь в данный момент онлайн, его сессия будет разорвана автоматически
    flash(f'Пользователь {user.username} заблокирован. Его сессия будет прервана при следующем запросе.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/unblock', methods=['POST'])
@admin_required
def admin_unblock_user(user_id):
    """Разблокировать пользователя"""
    user = User.query.get_or_404(user_id)
    
    if not user.is_blocked:
        flash('Этот пользователь не заблокирован.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user.is_blocked = False
    db.session.commit()
    
    flash(f'Пользователь {user.username} разблокирован.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Удалить пользователя"""
    # Защита от удаления себя
    if user_id == current_user.id:
        flash('Вы не можете удалить самого себя.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Защита от удаления админов
    if user.is_admin:
        flash('Вы не можете удалять администраторов системы.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    username = user.username
    # Удалить файлы пользователя
    delete_file_if_exists(user.avatar)
    delete_file_if_exists(user.contact_document)
    Review.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'Пользователь {username} удален.', 'success')
    return redirect(url_for('admin_dashboard'))

# ==================== Добавление кружка ====================
@app.route('/admin/course/add', methods=['GET', 'POST'])
@admin_required
def admin_add_course():
    """Добавить новый кружок"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        min_age = request.form.get('min_age', 14, type=int)
        max_age = request.form.get('max_age', 22, type=int)
        max_students = request.form.get('max_students', 20, type=int)
        schedule = request.form.get('schedule', '').strip()
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()
        instructor = request.form.get('instructor', '').strip()
        icon = request.form.get('icon', 'dumbbell').strip()
        
        if not name or not category:
            flash('Название и категория обязательны.', 'danger')
            return redirect(url_for('admin_add_course'))
        
        course = Course(
            name=name,
            description=description,
            category=category,
            min_age=min_age,
            max_age=max_age,
            max_students=max_students,
            schedule=schedule,
            address=address,
            phone=phone,
            instructor=instructor,
            icon=icon
        )
        db.session.add(course)
        db.session.flush()
        
        # Загрузка картинки курса
        if 'image' in request.files:
            file = request.files['image']
            if file:
                image_path = save_upload_file(file, 'courses')
                if image_path:
                    course.image = image_path
                else:
                    flash('Неверный формат файла изображения.', 'warning')

        # Загрузка изображений галереи
        gallery_files = request.files.getlist('gallery_images')
        saved_gallery = save_course_gallery_images(course.id, gallery_files)
        if gallery_files and not saved_gallery and any(f.filename for f in gallery_files):
            flash('Часть файлов галереи не загружена. Проверьте формат изображений.', 'warning')
        
        db.session.commit()
        
        flash(f'Кружок "{name}" успешно добавлен.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/add_course.html')

# ==================== Редактирование кружка ====================
@app.route('/admin/course/<int:course_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_course(course_id):
    """Редактировать кружок"""
    course = Course.query.get_or_404(course_id)
    
    if request.method == 'POST':
        course.name = request.form.get('name', '').strip()
        course.description = request.form.get('description', '').strip()
        course.category = request.form.get('category', '').strip()
        course.min_age = request.form.get('min_age', course.min_age, type=int)
        course.max_age = request.form.get('max_age', course.max_age, type=int)
        course.max_students = request.form.get('max_students', course.max_students, type=int)
        course.schedule = request.form.get('schedule', '').strip()
        course.address = request.form.get('address', '').strip()
        course.phone = request.form.get('phone', '').strip()
        course.instructor = request.form.get('instructor', '').strip()
        course.icon = request.form.get('icon', 'dumbbell').strip()
        
        # Загрузка новой картинки если загружена (удаляем старую)
        if 'image' in request.files:
            file = request.files['image']
            if file:
                image_path = save_upload_file(file, 'courses')
                if image_path:
                    old_image = course.image
                    course.image = image_path
                    delete_file_if_exists(old_image)
                else:
                    flash('Неверный формат файла изображения.', 'warning')

        # Удаление выбранных фото галереи
        delete_gallery = request.form.getlist('delete_gallery')
        for gpath in delete_gallery:
            delete_file_if_exists(gpath)

        # Дозагрузка изображений галереи
        gallery_files = request.files.getlist('gallery_images')
        save_course_gallery_images(course.id, gallery_files)
        
        course.updated_at = datetime.utcnow()
        
        if not course.name or not course.category:
            flash('Название и категория обязательны.', 'danger')
            return redirect(url_for('admin_edit_course', course_id=course_id))
        
        db.session.commit()
        flash(f'Кружок "{course.name}" успешно обновлен.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    gallery_images = get_course_gallery_images(course.id)
    return render_template('admin/edit_course.html', course=course, gallery_images=gallery_images)

# ==================== Удаление кружка ====================
@app.route('/admin/course/<int:course_id>/delete', methods=['POST'])
@admin_required
def admin_delete_course(course_id):
    """Удалить кружок + файлы с диска"""
    course = Course.query.get_or_404(course_id)
    course_name = course.name
    
    # Удалить обложку
    delete_file_if_exists(course.image)
    # Удалить галерею
    gallery_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'courses', 'gallery', str(course.id))
    if os.path.isdir(gallery_dir):
        shutil.rmtree(gallery_dir, ignore_errors=True)
    # Удалить отзывы
    Review.query.filter_by(course_id=course.id).delete()
    
    db.session.delete(course)
    db.session.commit()
    
    flash(f'Кружок "{course_name}" успешно удален.', 'success')
    return redirect(url_for('admin_dashboard'))

# ==================== Просмотр записавшихся на кружок ====================
@app.route('/admin/course/<int:course_id>/enrollments')
@admin_required
def admin_course_enrollments(course_id):
    """Просмотр списка записавшихся студентов"""
    course = Course.query.get_or_404(course_id)
    students = course.students.all()
    
    return render_template('admin/course_enrollments.html', course=course, students=students)

# ==================== Служебные функции ====================
def url_has_allowed_host_and_scheme(url):
    """Проверка безопасности URL для редиректов"""
    if not url:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, url))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# ==================== Обработка ошибок ====================
@app.errorhandler(404)
def page_not_found(error):
    """Страница не найдена"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Внутренняя ошибка сервера"""
    db.session.rollback()
    return render_template('errors/500.html'), 500

# ==================== CLI команды ====================
@app.cli.command()
def init_db():
    """Инициализация базы данных"""
    db.create_all()
    print('База данных инициализирована.')

@app.cli.command()
def seed_db():
    """Заполнение БД тестовыми данными"""
    # Создание/обновление администратора по умолчанию
    ensure_default_admin()
    
    # Тестовые кружки
    courses_data = [
        {
            'name': 'Футбол',
            'description': 'Обучение основам футбола, техника удара, тактика игры.',
            'category': 'sports',
            'min_age': 14,
            'max_age': 22,
            'max_students': 15,
            'schedule': 'пн, ср, пт 16:00-17:30',
            'instructor': 'Иван Петров',
            'icon': 'futbol'
        },
        {
            'name': 'Плавание',
            'description': 'Обучение различным стилям плавания, закаливание.',
            'category': 'sports',
            'min_age': 14,
            'max_age': 22,
            'max_students': 12,
            'schedule': 'вт, чт 15:00-16:00',
            'instructor': 'Елена Смирнова',
            'icon': 'water'
        },
        {
            'name': 'Рисование',
            'description': 'Развитие творческих способностей, изучение живописи и графики.',
            'category': 'art',
            'min_age': 14,
            'max_age': 22,
            'max_students': 20,
            'schedule': 'сб 10:00-12:00',
            'instructor': 'Анна Соколова',
            'icon': 'palette'
        },
        {
            'name': 'Программирование Python',
            'description': 'Изучение основ программирования на Python, создание простых приложений.',
            'category': 'science',
            'min_age': 14,
            'max_age': 22,
            'max_students': 18,
            'schedule': 'ср, сб 17:00-18:30',
            'instructor': 'Михаил Козлов',
            'icon': 'code'
        },
        {
            'name': 'Фортепиано',
            'description': 'Индивидуальные занятия по фортепиано для всех уровней.',
            'category': 'music',
            'min_age': 14,
            'max_age': 22,
            'max_students': 10,
            'schedule': 'по расписанию',
            'instructor': 'Наталья Волкова',
            'icon': 'music'
        },
        {
            'name': 'Каратэ',
            'description': 'Обучение каратэ, развитие дисциплины и боевых навыков.',
            'category': 'sports',
            'min_age': 14,
            'max_age': 22,
            'max_students': 16,
            'schedule': 'пн, пт 18:00-19:30',
            'instructor': 'Виктор Романов',
            'icon': 'dumbbell'
        },
        {
            'name': 'Танцы (Хип-хоп)',
            'description': 'Изучение современных танцевальных стилей, подготовка к выступлениям.',
            'category': 'art',
            'min_age': 14,
            'max_age': 22,
            'max_students': 20,
            'schedule': 'вт, чт 17:00-18:30',
            'instructor': 'Ксения Морозова',
            'icon': 'music'
        },
        {
            'name': 'Робототехника',
            'description': 'Конструирование и программирование роботов на базе популярных платформ.',
            'category': 'science',
            'min_age': 14,
            'max_age': 22,
            'max_students': 14,
            'schedule': 'сб 14:00-16:00',
            'instructor': 'Дмитрий Королев',
            'icon': 'code'
        },
    ]
    
    for course_data in courses_data:
        if not Course.query.filter_by(name=course_data['name']).first():
            course = Course(**course_data)
            db.session.add(course)
    
    db.session.commit()
    print('База данных заполнена тестовыми данными.')

# ==================== Новые маршруты админ-панели ====================

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard_main():
    """Главная страница админ-панели"""
    courses = Course.query.all()
    users = User.query.all()
    pending_admins = User.query.filter_by(user_type='circle_admin', is_approved=False).all()
    complaints = Complaint.query.filter_by(status='open').all()
    
    return render_template('admin/dashboard.html', 
                         courses=courses, 
                         users=users, 
                         pending_admins=pending_admins,
                         complaints=complaints)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Управление пользователями"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    
    query = User.query
    if search:
        query = query.filter((User.username.ilike(f'%{search}%')) | 
                            (User.email.ilike(f'%{search}%')) |
                            (User.first_name.ilike(f'%{search}%')))
    
    users = query.paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=users, search=search)

@app.route('/admin/courses')
@admin_required
def admin_courses():
    """Управление кружками"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    
    query = Course.query
    if search:
        query = query.filter(Course.name.ilike(f'%{search}%') | 
                            Course.category.ilike(f'%{search}%'))
    
    courses = query.paginate(page=page, per_page=20)
    return render_template('admin/courses.html', courses=courses, search=search)

@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    """Статистика"""
    total_users = User.query.count()
    total_courses = Course.query.count()
    total_enrollments = db.session.query(enrollment).count()
    total_complaints = Complaint.query.count()
    
    # Распределение по возрасту
    age_groups = {}
    for user in User.query.all():
        if user.age:
            group = f"{(user.age // 5) * 5}-{(user.age // 5) * 5 + 4}"
            age_groups[group] = age_groups.get(group, 0) + 1
    
    # Распределение по категориям кружков
    categories = {}
    for course in Course.query.all():
        categories[course.category] = categories.get(course.category, 0) + 1
    
    return render_template('admin/statistics.html',
                          total_users=total_users,
                          total_courses=total_courses,
                          total_enrollments=total_enrollments,
                          total_complaints=total_complaints,
                          age_groups=age_groups,
                          categories=categories)

@app.route('/admin/moderation')
@admin_required
def admin_moderation():
    """Модерация пользователей"""
    pending_admins = User.query.filter_by(user_type='circle_admin', is_approved=False).all()
    blocked_users = User.query.filter_by(is_blocked=True).all()
    
    return render_template('admin/moderation.html', 
                          pending_admins=pending_admins,
                          blocked_users=blocked_users)

@app.route('/admin/complaints')
@admin_required
def admin_complaints():
    """Просмотр жалоб"""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '').strip()
    
    query = Complaint.query
    if status:
        query = query.filter_by(status=status)
    
    complaints = query.order_by(Complaint.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('admin/complaints.html', complaints=complaints, current_status=status)

@app.route('/admin/complaints/<int:complaint_id>')
@admin_required
def admin_complaint_detail(complaint_id):
    """Просмотр и ответ на конкретную жалобу"""
    complaint = Complaint.query.get_or_404(complaint_id)
    return render_template('admin/complaint_detail.html', complaint=complaint)

@app.route('/admin/complaints/<int:complaint_id>/respond', methods=['POST'])
@admin_required
def admin_respond_complaint(complaint_id):
    """Дать ответ на жалобу"""
    complaint = Complaint.query.get_or_404(complaint_id)
    response = request.form.get('response', '').strip()
    new_status = request.form.get('status', 'in_review').strip()
    
    if not response:
        flash('Ответ не может быть пустым.', 'danger')
        return redirect(url_for('admin_complaint_detail', complaint_id=complaint_id))
    
    complaint.admin_response = response
    complaint.status = new_status
    complaint.responded_at = datetime.utcnow()
    db.session.commit()
    
    flash('Ответ на жалобу отправлен.', 'success')
    return redirect(url_for('admin_complaints'))

@app.route('/course/<int:course_id>/complain', methods=['GET', 'POST'])
@login_required
def submit_complaint(course_id):
    """Отправить жалобу на кружок"""
    course = Course.query.get_or_404(course_id)
    
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        
        if not title or not description:
            flash('Заполните все поля.', 'danger')
            return redirect(url_for('submit_complaint', course_id=course_id))
        
        complaint = Complaint(
            user_id=current_user.id,
            course_id=course_id,
            title=title,
            description=description
        )
        db.session.add(complaint)
        db.session.commit()
        
        flash('Ваша жалоба успешно отправлена. Администратор вскоре ответит.', 'success')
        return redirect(url_for('course_detail', course_id=course_id))
    
    return render_template('complaint_form.html', course=course)

@app.route('/my/complaints')
@login_required
def my_complaints():
    """Мои жалобы"""
    page = request.args.get('page', 1, type=int)
    complaints = current_user.complaints.order_by(Complaint.created_at.desc()).paginate(page=page, per_page=10)
    return render_template('my_complaints.html', complaints=complaints)

@app.route('/complaints/<int:complaint_id>')
@login_required
def complaint_detail(complaint_id):
    """Просмотр детали жалобы (для отправителя)"""
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Проверка: может ли пользователь просматривать эту жалобу
    if complaint.user_id != current_user.id and not current_user.is_admin:
        flash('Вам не разрешено просматривать эту жалобу.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('complaint_detail.html', complaint=complaint)

# ==================== Панель администратора кружка ====================
@app.route('/circle-admin')
@login_required
def circle_admin_dashboard():
    """Панель администратора кружка"""
    if current_user.user_type != 'circle_admin':
        flash('У вас нет прав доступа. Эта страница только для администраторов кружков.', 'danger')
        return redirect(url_for('profile'))
    
    if not current_user.is_approved:
        flash('Ваш аккаунт ждет одобрения администратора. Вы не можете пользоваться панелью администратора.', 'warning')
        return redirect(url_for('profile'))
    
    # В будущем здесь будут кружки, созданные этим администратором
    return render_template('circle_admin/dashboard.html', user=current_user)

# ==================== Создание кружка администратором кружка ====================
@app.route('/circle-admin/course/create', methods=['GET', 'POST'])
@login_required
def circle_admin_create_course():
    """Создать новый кружок (администратор кружка)"""
    if current_user.user_type != 'circle_admin' or not current_user.is_approved:
        flash('У вас нет прав доступа.', 'danger')
        return redirect(url_for('circle_admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        min_age = request.form.get('min_age', 14, type=int)
        max_age = request.form.get('max_age', 22, type=int)
        max_students = request.form.get('max_students', 20, type=int)
        schedule = request.form.get('schedule', '').strip()
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()
        icon = request.form.get('icon', 'dumbbell').strip()
        
        if not name or not category:
            flash('Название и категория обязательны.', 'danger')
            return redirect(url_for('circle_admin_create_course'))
        
        instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip()
        course = Course(
            name=name,
            description=description,
            category=category,
            min_age=min_age,
            max_age=max_age,
            max_students=max_students,
            schedule=schedule,
            address=address,
            phone=phone,
            instructor=instructor_name or current_user.username,
            icon=icon
        )
        db.session.add(course)
        db.session.flush()
        
        # Загрузка картинки курса
        if 'image' in request.files:
            file = request.files['image']
            if file:
                image_path = save_upload_file(file, 'courses')
                if image_path:
                    course.image = image_path
                else:
                    flash('Неверный формат файла изображения.', 'warning')

        # Загрузка изображений галереи
        gallery_files = request.files.getlist('gallery_images')
        saved_gallery = save_course_gallery_images(course.id, gallery_files)
        if gallery_files and not saved_gallery and any(f.filename for f in gallery_files):
            flash('Часть файлов галереи не загружена. Проверьте формат изображений.', 'warning')
        
        db.session.commit()
        
        flash(f'Кружок "{name}" успешно создан.', 'success')
        return redirect(url_for('circle_admin_courses'))
    
    return render_template('circle_admin/create_course.html')

# ==================== Просмотр кружков администратора кружка ====================
@app.route('/circle-admin/courses')
@login_required
def circle_admin_courses():
    """Просмотр своих кружков (администратор кружка)"""
    if current_user.user_type != 'circle_admin':
        flash('У вас нет прав доступа.', 'danger')
        return redirect(url_for('circle_admin_dashboard'))
    
    # Получить все кружки, созданные этим администратором
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip()
    courses = Course.query.filter_by(instructor=instructor_name or current_user.username).all()
    
    return render_template('circle_admin/courses.html', courses=courses)

# ==================== Статистика администратора кружка ====================
@app.route('/circle-admin/statistics')
@login_required
def circle_admin_statistics():
    """Статистика по кружкам (администратор кружка)"""
    if current_user.user_type != 'circle_admin':
        flash('У вас нет прав доступа.', 'danger')
        return redirect(url_for('circle_admin_dashboard'))
    
    # Получить все кружки этого администратора
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip()
    courses = Course.query.filter_by(instructor=instructor_name or current_user.username).all()
    
    # Подсчитать статистику
    stats = {
        'total_courses': len(courses),
        'total_students': sum([course.enrollment_count for course in courses]),
        'total_slots': sum([course.available_slots for course in courses])
    }
    
    return render_template('circle_admin/statistics.html', courses=courses, stats=stats)

# ==================== Редактирование кружка администратором кружка ====================
@app.route('/circle-admin/course/<int:course_id>/edit', methods=['GET', 'POST'])
@login_required
def circle_admin_edit_course(course_id):
    """Редактировать кружок (администратор кружка)"""
    course = Course.query.get_or_404(course_id)
    
    # Проверка, что это кружок этого администратора
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if course.instructor != instructor_name:
        flash('У вас нет прав на редактирование этого кружка.', 'danger')
        return redirect(url_for('circle_admin_courses'))
    
    if request.method == 'POST':
        course.name = request.form.get('name', '').strip()
        course.description = request.form.get('description', '').strip()
        course.category = request.form.get('category', '').strip()
        course.min_age = request.form.get('min_age', 14, type=int)
        course.max_age = request.form.get('max_age', 22, type=int)
        course.max_students = request.form.get('max_students', 20, type=int)
        course.schedule = request.form.get('schedule', '').strip()
        course.address = request.form.get('address', '').strip()
        course.phone = request.form.get('phone', '').strip()
        course.icon = request.form.get('icon', 'dumbbell').strip()
        
        if not course.name or not course.category:
            flash('Название и категория обязательны.', 'danger')
            return redirect(url_for('circle_admin_edit_course', course_id=course_id))
        
        # Загрузка картинки курса если предоставлена (удаляем старую)
        if 'image' in request.files:
            file = request.files['image']
            if file:
                image_path = save_upload_file(file, 'courses')
                if image_path:
                    old_image = course.image
                    course.image = image_path
                    delete_file_if_exists(old_image)
                else:
                    flash('Неверный формат файла изображения.', 'warning')

        # Удаление выбранных фото галереи
        delete_gallery = request.form.getlist('delete_gallery')
        for gpath in delete_gallery:
            delete_file_if_exists(gpath)

        # Дозагрузка изображений галереи
        gallery_files = request.files.getlist('gallery_images')
        save_course_gallery_images(course.id, gallery_files)
        
        course.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Кружок "{course.name}" успешно обновлен.', 'success')
        return redirect(url_for('circle_admin_courses'))
    
    gallery_images = get_course_gallery_images(course.id)
    return render_template('circle_admin/edit_course.html', course=course, gallery_images=gallery_images)

# ==================== Удаление кружка администратором кружка ====================
@app.route('/circle-admin/course/<int:course_id>/delete', methods=['POST'])
@login_required
def circle_admin_delete_course(course_id):
    """Удалить кружок (администратор кружка) + файлы"""
    course = Course.query.get_or_404(course_id)
    
    # Проверка, что это кружок этого администратора
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if course.instructor != instructor_name:
        flash('У вас нет прав на удаление этого кружка.', 'danger')
        return redirect(url_for('circle_admin_courses'))
    
    course_name = course.name
    delete_file_if_exists(course.image)
    gallery_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'courses', 'gallery', str(course.id))
    if os.path.isdir(gallery_dir):
        shutil.rmtree(gallery_dir, ignore_errors=True)
    Review.query.filter_by(course_id=course.id).delete()
    
    db.session.delete(course)
    db.session.commit()
    
    flash(f'Кружок "{course_name}" успешно удален.', 'success')
    return redirect(url_for('circle_admin_courses'))

# ==================== Просмотр студентов кружка ====================
@app.route('/circle-admin/course/<int:course_id>/students')
@login_required
def circle_admin_students(course_id):
    """Просмотр студентов, записанных на кружок"""
    if current_user.user_type != 'circle_admin':
        flash('У вас нет прав доступа.', 'danger')
        return redirect(url_for('circle_admin_dashboard'))
    
    course = Course.query.get_or_404(course_id)
    
    # Проверка прав собственности
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if course.instructor != instructor_name:
        flash('У вас нет прав на просмотр студентов этого кружка.', 'danger')
        return redirect(url_for('circle_admin_courses'))
    
    # Получить одобренных студентов
    students = course.students.all()
    # Получить заявки на рассмотрении
    pending_requests = EnrollmentRequest.query.filter_by(
        course_id=course_id, status='pending'
    ).order_by(EnrollmentRequest.created_at.desc()).all()
    
    return render_template('circle_admin/course_students.html',
                           course=course, students=students, pending_requests=pending_requests)

# ==================== Удаление студента из кружка ====================
@app.route('/circle-admin/course/<int:course_id>/remove-student/<int:student_id>', methods=['POST'])
@login_required
def circle_admin_remove_student(course_id, student_id):
    """Удалить студента из кружка"""
    if current_user.user_type != 'circle_admin':
        flash('У вас нет прав доступа.', 'danger')
        return redirect(url_for('circle_admin_dashboard'))
    
    course = Course.query.get_or_404(course_id)
    student = User.query.get_or_404(student_id)
    
    # Проверка прав собственности
    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if course.instructor != instructor_name:
        flash('У вас нет прав на удаление студентов из этого кружка.', 'danger')
        return redirect(url_for('circle_admin_courses'))
    
    # Проверка, записан ли студент на этот кружок
    if student not in course.students:
        flash('Этот студент не записан на данный кружок.', 'danger')
        return redirect(url_for('circle_admin_students', course_id=course_id))
    
    # Удаление студента из кружка
    course.students.remove(student)
    db.session.commit()
    
    flash(f'Студент {student.username} удален из кружка "{course.name}".', 'success')
    return redirect(url_for('circle_admin_students', course_id=course_id))

# ==================== Одобрение / отклонение заявки ====================
@app.route('/circle-admin/enrollment/<int:request_id>/approve', methods=['POST'])
@login_required
def circle_admin_approve_enrollment(request_id):
    """Одобрить заявку на запись"""
    er = EnrollmentRequest.query.get_or_404(request_id)
    course = Course.query.get_or_404(er.course_id)

    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if current_user.user_type != 'circle_admin' or course.instructor != instructor_name:
        flash('У вас нет прав.', 'danger')
        return redirect(url_for('circle_admin_courses'))

    if course.is_full:
        flash('Нет свободных мест, невозможно одобрить.', 'warning')
        return redirect(url_for('circle_admin_students', course_id=course.id))

    # Одобряем: добавляем студента в кружок
    student = User.query.get(er.user_id)
    if student and student not in course.students.all():
        student.courses.append(course)
    er.status = 'approved'
    er.resolved_at = datetime.utcnow()
    db.session.commit()
    flash(f'Студент {student.username} одобрен.', 'success')
    return redirect(url_for('circle_admin_students', course_id=course.id))


@app.route('/circle-admin/enrollment/<int:request_id>/reject', methods=['POST'])
@login_required
def circle_admin_reject_enrollment(request_id):
    """Отклонить заявку на запись"""
    er = EnrollmentRequest.query.get_or_404(request_id)
    course = Course.query.get_or_404(er.course_id)

    instructor_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.username
    if current_user.user_type != 'circle_admin' or course.instructor != instructor_name:
        flash('У вас нет прав.', 'danger')
        return redirect(url_for('circle_admin_courses'))

    er.status = 'rejected'
    er.resolved_at = datetime.utcnow()
    db.session.commit()
    flash('Заявка отклонена.', 'info')
    return redirect(url_for('circle_admin_students', course_id=course.id))

# Демо-админ при каждой загрузке приложения (в т.ч. gunicorn): admin / admin123
with app.app_context():
    db.create_all()
    ensure_default_admin()

if __name__ == '__main__':
    host = os.environ.get('APP_HOST', '0.0.0.0')
    port = int(os.environ.get('APP_PORT', '5000'))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug, host=host, port=port)
