import os
import random
import time
import mimetypes              # ← вот это вы забыли добавить
from datetime import datetime, timedelta

from itsdangerous import URLSafeTimedSerializer
import pytz
import requests
import json

from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, jsonify, Response, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from flask_mail import Mail, Message               # ← убедитесь, что этот пакет установлен
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import OAuth2ConsumerBlueprint
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()   # автоматически подхватит .env из корня проекта


from flask_migrate import Migrate


app = Flask(__name__)
app.config['SECRET_KEY']              = os.environ['SECRET_KEY']
app.config['SECURITY_PASSWORD_SALT']  = os.environ['SECURITY_PASSWORD_SALT']
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Почтовая служба для подтверждений, сброса пароля и 2FA
app.config['MAIL_SERVER']   = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT']     = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('EventPoint', 'no-reply@example.com')

# OAuth
# включаем «небезопасный» transport, чтобы OAuth работал по http://localhost
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = True
app.config['GOOGLE_OAUTH_CLIENT_ID']     = os.environ['GOOGLE_OAUTH_CLIENT_ID']
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ['GOOGLE_OAUTH_CLIENT_SECRET']
app.config['VK_OAUTH_CLIENT_ID']         = os.environ['VK_OAUTH_CLIENT_ID']
app.config['VK_OAUTH_CLIENT_SECRET']     = os.environ['VK_OAUTH_CLIENT_SECRET']


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# OAuth blueprints
google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_url="/oauth/google"
)
vk_bp = OAuth2ConsumerBlueprint(
    "vk",                          # имя blueprint’а
    __name__,                      # import_name
    client_id=app.config["VK_OAUTH_CLIENT_ID"],
    client_secret=app.config["VK_OAUTH_CLIENT_SECRET"],
    base_url="https://api.vk.com/method/",
    authorization_url="https://oauth.vk.com/authorize",
    token_url="https://oauth.vk.com/access_token",
    redirect_to="vk_authorized"    # endpoint, куда VK вернётся после логина
)

# Разрешаем небезопасный HTTP для OAuth в локальной разработке
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"      # <-- вот эта строка
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(vk_bp,     url_prefix="/login")
login_manager.login_view = 'login'

# Flask-Migrate для миграций
from flask_migrate import Migrate
migrate = Migrate(app, db)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Таблица регистрации на мероприятия
attendances = db.Table('attendances',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), primary_key=True)
)

# Таблица для хранения связей друзей (симметричная связь)
friendships = db.Table('friendships',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('friend_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
)

# Новые ассоциативные таблицы для избранного
favorite_tags = db.Table('favorite_tags',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
)

favorite_organizers = db.Table('favorite_organizers',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('organizer_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
)

# Модель заявок в друзья
class FriendRequest(db.Model):
    __tablename__ = 'friend_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_requests")
    recipient = db.relationship("User", foreign_keys=[recipient_id], backref="received_requests")

# Модель для таблицы EventMedia (слайдшоу)
class EventMedia(db.Model):
    __tablename__ = 'event_media'
    id = db.Column(db.Integer, primary_key=True)
    image_data = db.Column(db.LargeBinary, nullable=False)
    caption = db.Column(db.Text)
    mime_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Модель пользователя
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # participant, organizer, moderator, administrator
    two_factor_enabled = db.Column(db.Boolean, default=True)
    # Новые поля для аккредитации:
    accreditation_status = db.Column(db.String(20), default='not_submitted')
    accreditation_rejection_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    events = db.relationship('Event', backref='organizer', lazy=True)
    avatar_filename = db.Column(db.String(255), nullable=False, default='participant_avatar_none.png')
    # Новые поля для организатора:
    organization_name = db.Column(db.String(255))      # Наименование организации
    description = db.Column(db.Text)                     # Краткое описание
    activity_field = db.Column(db.String(255))           # Сфера деятельности
    attended_events = db.relationship('Event', secondary=attendances,
                                      backref=db.backref('attendees', lazy='dynamic'),
                                      lazy='subquery')
    friends = db.relationship('User', secondary=friendships,
                              primaryjoin=(id == friendships.c.user_id),
                              secondaryjoin=(id == friendships.c.friend_id),
                              backref=db.backref('friend_of', lazy='dynamic'),
                              lazy='dynamic')
    # Новые отношения для избранного
    favorite_tags = db.relationship('Tag', secondary=favorite_tags,
                                    backref=db.backref('favorited_by', lazy='dynamic'),
                                    lazy='dynamic')
    favorite_organizers = db.relationship('User', secondary=favorite_organizers,
                                          primaryjoin=(id == favorite_organizers.c.user_id),
                                          secondaryjoin=(id == favorite_organizers.c.organizer_id),
                                          backref=db.backref('favorited_by_organizer', lazy='dynamic'),
                                          lazy='dynamic')
    # Видимость списка мероприятий: "none", "all", "friends"
    events_visibility = db.Column(db.String(20), default='all')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Пример модели события:
class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    event_format = db.Column(db.String(20), nullable=False)  # online или offline
    location = db.Column(db.String(255))
    event_date = db.Column(db.DateTime)
    duration = db.Column(db.Integer)  # длительность в минутах
    contacts = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    category = db.Column(db.String(50), nullable=True)
    tags = db.relationship('Tag', secondary='event_tags', lazy='subquery',
                           backref=db.backref('events', lazy=True))
    files = db.relationship('EventFile', backref='event', lazy=True)


# Модель файлов мероприятия
class EventFile(db.Model):
    __tablename__ = 'event_files'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Модель тегов
class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __str__(self):
        return self.name

event_tags = db.Table('event_tags',
    db.Column('event_id', db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
)

class EventInvitation(db.Model):
    __tablename__ = 'event_invitations'
    id = db.Column(db.Integer, primary_key=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    invitee_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # отношения
    inviter = db.relationship("User", foreign_keys=[inviter_id], backref="sent_invitations")
    invitee = db.relationship("User", foreign_keys=[invitee_id], backref="received_invitations")
    event = db.relationship("Event", foreign_keys=[event_id])

# File: app.py
# Обновлённая модель AccreditationApplication с дополнительными полями для хранения исходных имён файлов

class AccreditationApplication(db.Model):
    __tablename__ = 'accreditation_applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    person_type = db.Column(db.String(20), nullable=False)  # 'physical' или 'legal'
    # Поля для физических лиц
    full_name = db.Column(db.String(512))
    date_of_birth = db.Column(db.Date)
    registration_address = db.Column(db.String(512))
    phone = db.Column(db.String(50))
    resume = db.Column(db.Text)
    # Поля для юридических лиц
    organization_name = db.Column(db.String(512))
    legal_address = db.Column(db.String(512))
    actual_address = db.Column(db.String(512))
    ceo_name = db.Column(db.String(512))
    website = db.Column(db.String(512))
    social_links = db.Column(db.Text)
    company_description = db.Column(db.Text)
    # Документы (будут храниться как бинарные данные):
    passport_copy = db.Column(db.LargeBinary, nullable=True)
    individual_registration_doc = db.Column(db.LargeBinary, nullable=True)
    egrul_extract = db.Column(db.LargeBinary, nullable=True)
    tax_certificate = db.Column(db.LargeBinary, nullable=True)
    license_doc = db.Column(db.LargeBinary, nullable=True)
    professional_experience_docs = db.Column(db.LargeBinary, nullable=True)
    # Новые поля для хранения исходных имён файлов
    passport_copy_filename = db.Column(db.String(255), nullable=True)
    individual_registration_doc_filename = db.Column(db.String(255), nullable=True)
    egrul_extract_filename = db.Column(db.String(255), nullable=True)
    tax_certificate_filename = db.Column(db.String(255), nullable=True)
    license_doc_filename = db.Column(db.String(255), nullable=True)
    professional_experience_docs_filename = db.Column(db.String(255), nullable=True)
    # Дополнительные сведения
    consent = db.Column(db.Boolean, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    moderator_reason = db.Column(db.Text, nullable=True)  # При отклонении заявки
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='accreditation_applications')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_file_url(file_id):
    return url_for('get_file', file_id=file_id)

# Функция для преобразования события в словарь для передачи в шаблон
def event_to_dict(event):
    file_urls = [get_file_url(f.id) for f in event.files]
    result = {
        "id": event.id,
        "title": event.title,
        "description": event.description,
        "event_format": event.event_format,
        "location": event.location,
        "event_date": event.event_date.strftime('%Y-%m-%d %H:%M') if event.event_date else "",
        "duration": event.duration,
        "contacts": event.contacts,
        "latitude": event.latitude,
        "longitude": event.longitude,
        "organizer_name": event.organizer.name if event.organizer else "Не указан",
        "organizer_id": event.organizer.id if event.organizer else None,
        "files": file_urls,
        "images": file_urls,
        "tags": [tag.name for tag in event.tags],
        "category": event.category or "",
        "attendees_count": event.attendees.count(),
        "active": is_event_active(event),
        "in_progress": is_event_in_progress(event)  # новое поле
    }
    if file_urls:
        result["file_thumbnail"] = file_urls[0]
        if len(file_urls) >= 2:
            result["second_image"] = file_urls[1]
        if len(file_urls) >= 3:
            result["third_image"] = file_urls[2]
        result["extra_images_count"] = len(file_urls) - 3 if len(file_urls) > 3 else 0
    return result

# Функция для вычисления, завершилось ли событие
def is_event_active(event):
    # Если event_date или duration не заданы, считаем событие активным
    if not event.event_date or not event.duration:
        return True

    # Определяем временную зону – например, для Москвы:
    tz = pytz.timezone("Europe/Moscow")

    # Если event.event_date не является timezone-aware, делаем его такими:
    if event.event_date.tzinfo is None:
        event_date_local = tz.localize(event.event_date)
    else:
        event_date_local = event.event_date.astimezone(tz)

    event_end = event_date_local + timedelta(minutes=event.duration)
    now = datetime.now(tz).replace(second=0, microsecond=0)
    return event_end > now

def is_event_in_progress(event):
    # Если event_date или duration не заданы, возвращаем False (не идёт)
    if not event.event_date or not event.duration:
        return False
    tz = pytz.timezone("Europe/Moscow")
    # Если event_date не timezone-aware, делаем его таковым:
    if event.event_date.tzinfo is None:
        event_date_local = tz.localize(event.event_date)
    else:
        event_date_local = event.event_date.astimezone(tz)
    event_end = event_date_local + timedelta(minutes=event.duration)
    now = datetime.now(tz).replace(second=0, microsecond=0)
    return event_date_local <= now < event_end

@app.route('/files/<int:file_id>')
def get_file(file_id):
    file_record = EventFile.query.get_or_404(file_id)
    return Response(file_record.file_data, mimetype=file_record.mime_type)

# Новый маршрут для отдачи изображений из EventMedia (слайдшоу)
@app.route('/media/<int:media_id>')
def get_media(media_id):
    media = EventMedia.query.get_or_404(media_id)
    return Response(media.image_data, mimetype=media.mime_type)

# Новый маршрут для загрузки изображений в слайдшоу (для администратора)
@app.route('/upload_media', methods=['GET', 'POST'])
@login_required
def upload_media():
    if current_user.role != 'administrator':
        flash("Доступ разрешён только администраторам.")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'media' not in request.files:
            flash("Файл не выбран для загрузки.")
            return redirect(url_for('upload_media'))
        file = request.files['media']
        caption = request.form.get('caption')
        if file and allowed_file(file.filename):
            new_media = EventMedia(
                image_data=file.read(),
                caption=caption,
                mime_type=file.mimetype
            )
            db.session.add(new_media)
            db.session.commit()
            return redirect(url_for('administrator_dashboard'))
        else:
            flash("Неподдерживаемый формат файла.")
            return redirect(url_for('upload_media'))
    return render_template('upload_media.html')

# Новый маршрут для удаления изображений из слайдшоу (для администратора)
@app.route('/delete_media/<int:media_id>', methods=['POST'])
@login_required
def delete_media(media_id):
    if current_user.role != 'administrator':
        flash("Доступ разрешён только администраторам.")
        return redirect(url_for('dashboard'))
    media = EventMedia.query.get_or_404(media_id)
    db.session.delete(media)
    db.session.commit()
    return redirect(url_for('administrator_dashboard'))


# Пример изменения маршрута index:
@app.route('/')
def index():
    current_category = request.args.get('category', 'Все')
    favorites_filter = request.args.get('favorites', '0')
    query = Event.query.order_by(Event.event_date)
    if current_category and current_category != 'Все':
        query = query.filter(Event.category == current_category)
    events = query.all()

    # Фильтруем только активные мероприятия (ещё не завершившиеся)
    events = [e for e in events if is_event_active(e)]

    # Фильтрация по избранному для участников
    if current_user.is_authenticated and current_user.role == 'participant' and favorites_filter == '1':
        filtered_events = []
        for e in events:
            is_fav = any(tag in current_user.favorite_tags for tag in e.tags) or (
                        e.organizer in current_user.favorite_organizers)
            if is_fav:
                filtered_events.append(e)
        events = filtered_events

    events_data = [event_to_dict(e) for e in events]
    attended_ids = []
    if current_user.is_authenticated and current_user.role == 'participant':
        attended_ids = [e.id for e in current_user.attended_events]
    media_items = EventMedia.query.order_by(EventMedia.created_at.desc()).all()
    media_data = [{'id': m.id, 'image_url': url_for('get_media', media_id=m.id), 'caption': m.caption} for m in
                  media_items]
    return render_template('index.html', events=events_data, attended_ids=attended_ids,
                           media_items=media_data, current_category=current_category, favorites_filter=favorites_filter)


# Регистрация с подтверждением email
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        role = request.form.get('role')
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует.')
            return redirect(url_for('register'))
        user = User(email=email, name=name, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        # Отправляем письмо для подтверждения регистрации
        token = serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email/confirm.html', confirm_url=confirm_url)
        msg = Message('Подтверждение регистрации', recipients=[user.email], html=html)
        mail.send(msg)
        flash('Проверьте почту для подтверждения регистрации.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('Ссылка недействительна или устарела.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('Аккаунт уже подтвержден. Войдите.', 'success')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('Ваш аккаунт подтверждён!', 'success')
    return redirect(url_for('login'))

# Вход с двухфакторной аутентификацией
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Неверные логин или пароль.', 'danger')
            return redirect(url_for('login'))
        if not user.email_confirmed:
            flash('Подтвердите свой аккаунт через ссылку в почте.', 'warning')
            return redirect(url_for('login'))
        # Генерация кода для 2FA
        if user.two_factor_enabled:
            code = '{:06d}'.format(random.randint(0, 999999))
            session['2fa_user_id'] = user.id
            session['2fa_code'] = code
            session['2fa_time'] = time.time()
            # Отправляем код на почту
            msg = Message('Ваш код для входа', recipients=[user.email])
            msg.body = f'Ваш код для входа: {code}'
            mail.send(msg)
            return redirect(url_for('two_factor'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    user_id = session.get('2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form.get('code')
        stored_code = session.get('2fa_code')
        sent_time = session.get('2fa_time', 0)
        if code == stored_code and time.time() - sent_time < 300:
            user = User.query.get(user_id)
            login_user(user)
            session.pop('2fa_code', None)
            session.pop('2fa_user_id', None)
            session.pop('2fa_time', None)
            return redirect(url_for('dashboard'))
        flash('Неверный или устаревший код.', 'danger')
        return redirect(url_for('two_factor'))
    return render_template('two_factor.html')

# Восстановление пароля
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('email/reset.html', reset_url=reset_url)
            msg = Message('Сброс пароля', recipients=[user.email], html=html)
            mail.send(msg)
        flash('Письмо с инструкциями по сбросу пароля отправлено.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('Ссылка недействительна или устарела.', 'danger')
        return redirect(url_for('reset_password_request'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if password != password2:
            flash('Пароли не совпадают.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user.set_password(password)
        db.session.commit()
        flash('Ваш пароль обновлен.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route("/oauth/vk")
def vk_authorized():
    # Если ещё не авторизовались у VK — перенаправляем на их логин
    if not vk_bp.session.authorized:
        return redirect(url_for("vk.login"))

    # Токен VK-а содержит access_token, expires_in, user_id и (если запросили) email
    token = vk_bp.token
    vk_user_id = token.get("user_id")
    email      = token.get("email")

    # Если VK не вернул email — придётся попросить пользователя собрать профиль вручную
    if not email:
        flash("Не удалось получить email из VK. Пожалуйста, зарегистрируйтесь вручную.", "warning")
        return redirect(url_for("register"))

    # Запрашиваем у VK остальную информацию о пользователе
    resp = vk_bp.session.get(
        "users.get",
        params={
            "user_ids": vk_user_id,
            "fields": "first_name,last_name",
            "v": "5.131"
        }
    )
    resp.raise_for_status()
    data = resp.json().get("response", [])
    if not data:
        flash("Не удалось получить данные профиля VK.", "danger")
        return redirect(url_for("login"))

    user_info = data[0]
    name = f"{user_info.get('first_name','')} {user_info.get('last_name','')}".strip()

    # Ищем пользователя в своей БД
    user = User.query.filter_by(email=email).first()
    if not user:
        # Создаём нового участника с подтверждённым email
        user = User(
            email=email,
            name=name or email,
            role="participant",
            email_confirmed=True
        )
        # Генерируем случайный пароль, чтобы никто не вошёл по нему
        user.set_password(os.urandom(16).hex())
        db.session.add(user)
        db.session.commit()

    # Логиним в систему
    login_user(user)
    return redirect(url_for("dashboard"))

@app.route("/oauth/google")
def google_authorized():
    # если ещё не залогинены через Google — кидаем на форму Google
    if not google.authorized:
        return redirect(url_for("google.login"))

    # получаем профиль пользователя
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Не удалось получить данные от Google.", "danger")
        return redirect(url_for("login"))

    info = resp.json()
    email = info.get("email")
    name  = info.get("name", email.split("@")[0])

    # ищем или создаём пользователя в БД
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            name=name,
            role="participant",
            email_confirmed=True
        )
        # ставим рандомный пароль, чтобы никто не мог зайти по нему
        user.set_password(os.urandom(16).hex())
        db.session.add(user)
        db.session.commit()

    # логиним
    login_user(user)
    return redirect(url_for("dashboard"))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ==== Кабинеты модератора, администратора и универсальный dashboard ====

@app.route('/moderator_dashboard')
@login_required
def moderator_dashboard():
    if current_user.role != 'moderator':
        flash("Доступ только для модераторов.")
        return redirect(url_for('dashboard'))

    users = User.query.all()
    events = Event.query.order_by(Event.event_date).all()

    # Список всех названий тегов
    all_tags = [t.name for t in Tag.query.order_by(Tag.name).all()]

    return render_template(
        'moderator_dashboard.html',
        users=users,
        events=[event_to_dict(e) for e in events],
        all_tags=all_tags
    )

@app.route('/administrator_dashboard')
@login_required
def administrator_dashboard():
    if current_user.role != 'administrator':
        flash("Доступ только для администраторов.")
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.created_at).all()
    events = Event.query.order_by(Event.event_date).all()
    media_items = EventMedia.query.order_by(EventMedia.created_at.desc()).all()
    media_data = [{'id': m.id, 'image_url': url_for('get_media', media_id=m.id), 'caption': m.caption} for m in media_items]
    # Добавили подсчёт заявок на аккредитацию в статусе "pending"
    pending_count = AccreditationApplication.query.filter_by(status='pending').count()
    all_tags = [t.name for t in Tag.query.order_by(Tag.name).all()]
    return render_template(
        'administrator_dashboard.html',
        users=users,
        events=[event_to_dict(e) for e in events],
        media=media_data,
        accreditation_count=pending_count,
        all_tags = all_tags
    )

# В dashboard для участников тоже фильтруем события
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'organizer':
        # Используем собственные мероприятия организатора
        own_events = current_user.events
        upcoming_events = [e for e in own_events if is_event_active(e)]
        past_events = [e for e in own_events if not is_event_active(e)]
        return render_template('organizer_dashboard.html',
                               upcoming_events=[event_to_dict(e) for e in upcoming_events],
                               past_events=[event_to_dict(e) for e in past_events])
    elif current_user.role == 'participant':
        attended_events = current_user.attended_events
        upcoming_events = [e for e in attended_events if is_event_active(e)]
        past_events = [e for e in attended_events if not is_event_active(e)]
        return render_template('participant_dashboard.html',
                               upcoming_events=[event_to_dict(e) for e in upcoming_events],
                               past_events=[event_to_dict(e) for e in past_events])
    elif current_user.role == 'moderator':
        return redirect(url_for('moderator_dashboard'))
    elif current_user.role == 'administrator':
        return redirect(url_for('administrator_dashboard'))
    else:
        flash('Неизвестная роль.')
        return redirect(url_for('index'))


@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event_obj = Event.query.get_or_404(event_id)
    event = event_to_dict(event_obj)
    attendees_ids = [user.id for user in event_obj.attendees]  # список ID уже записанных пользователей
    return render_template('event_detail.html', event=event, attendees_ids=attendees_ids)

@app.route('/toggle_attendance/<int:event_id>', methods=['POST'])
@login_required
def toggle_attendance(event_id):
    if current_user.role != 'participant':
        flash("Только участники могут регистрироваться на мероприятия.")
        return redirect(url_for('event_detail', event_id=event_id))
    event = Event.query.get_or_404(event_id)
    if event in current_user.attended_events:
        current_user.attended_events.remove(event)
    else:
        current_user.attended_events.append(event)
    db.session.commit()
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/geocode')
def geocode_route():
    query = request.args.get('q')
    if not query:
        return jsonify({"error": "No query provided"}), 400
    api_key = "db080a73-5fc1-450e-9791-fddb3db87ac9"  # замените на действительный ключ
    url = f"https://geocode-maps.yandex.ru/1.x/?apikey={api_key}&format=json&results=5&lang=ru_RU&geocode=" + requests.utils.quote(query)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            app.logger.error("Yandex Geocoder error: %s", response.text)
            return jsonify({"error": "Yandex Geocoder error: " + response.text}), response.status_code
        data = response.json()
    except requests.exceptions.RequestException as e:
        app.logger.error("Exception during Yandex Geocoder request: %s", e, exc_info=True)
        return jsonify({"error": str(e)}), 500
    return jsonify(data)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    # Только организаторы могут создавать события
    if current_user.role != 'organizer':
        flash('У вас нет прав для создания события.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Считываем поля формы
        title = request.form.get('title')
        description = request.form.get('description')
        event_format = request.form.get('event_format')
        location = request.form.get('location')
        event_date_str = request.form.get('event_date')
        duration = request.form.get('duration')
        contacts = request.form.get('contacts')
        # Теги теперь приходят как список имён тегов в скрытом поле selected_tags
        # (например, JSON, который вы собираете на клиенте)
        selected_tags = request.form.getlist('selected_tags[]')

        try:
            event_date = datetime.strptime(event_date_str, '%Y-%m-%d %H:%M')
        except ValueError:
            flash('Неверный формат даты и времени.')
            return redirect(url_for('create_event'))

        # Создаём сам объект события
        event = Event(
            title=title,
            description=description,
            event_format=event_format,
            location=location,
            event_date=event_date,
            duration=int(duration) if duration else None,
            contacts=contacts,
            organizer_id=current_user.id,
            category=request.form.get('category')
        )
        db.session.add(event)
        db.session.flush()  # чтобы получить event.id до коммита

        # Геокодирование адреса (если требуется)
        if location:
            yandex_api_key = "db080a73-5fc1-450e-9791-fddb3db87ac9"
            geocode_url = (
                "https://geocode-maps.yandex.ru/1.x/"
                f"?apikey={yandex_api_key}&format=json&results=1&lang=ru_RU&geocode="
                + requests.utils.quote(location)
            )
            try:
                geo_resp = requests.get(geocode_url, timeout=10)
                geo_resp.raise_for_status()
                geo_data = geo_resp.json()
                members = (
                    geo_data.get("response", {})
                    .get("GeoObjectCollection", {})
                    .get("featureMember", [])
                )
                if members:
                    pos = members[0]["GeoObject"]["Point"]["pos"]
                    lon, lat = pos.split()
                    event.latitude = float(lat)
                    event.longitude = float(lon)
                else:
                    flash("Неверный адрес. Пожалуйста, выберите существующий адрес.")
                    db.session.rollback()
                    return redirect(url_for('create_event'))
            except Exception as e:
                db.session.rollback()
                return redirect(url_for('create_event'))

        # Обработка тегов: ищем или создаём новые
        event.tags = []
        for name in selected_tags:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
                db.session.flush()
            event.tags.append(tag)

        # Обработка загружаемых изображений (если есть)
        if 'images' in request.files:
            for file in request.files.getlist('images'):
                if file and allowed_file(file.filename):
                    data = file.read()
                    event_file = EventFile(
                        event_id=event.id,
                        file_data=data,
                        mime_type=file.mimetype
                    )
                    db.session.add(event_file)

        # Сохраняем все изменения
        db.session.commit()
        return redirect(url_for('dashboard'))

    # GET-запрос — рендерим форму и передаём в неё список всех тегов
    tags = Tag.query.order_by(Tag.name).all()
    all_tags = [t.name for t in tags]
    return render_template('create_event.html', all_tags=all_tags)


# ===== Функционал для работы с заявками в друзья =====

@app.route('/send_friend_request/<int:friend_id>', methods=['POST'])
@login_required
def send_friend_request(friend_id):
    if friend_id == current_user.id:
        flash("Нельзя отправить запрос самому себе.")
        return redirect(url_for('find_friends'))
    friend = User.query.get_or_404(friend_id)
    if friend in current_user.friends.all():
        flash("Этот пользователь уже у вас в друзьях.")
        return redirect(url_for('find_friends'))
    existing_request = FriendRequest.query.filter_by(sender_id=current_user.id, recipient_id=friend_id, status='pending').first()
    if existing_request:
        flash("Запрос уже отправлен.")
        return redirect(url_for('find_friends'))
    new_request = FriendRequest(sender_id=current_user.id, recipient_id=friend_id)
    db.session.add(new_request)
    db.session.commit()
    flash("Запрос на добавление в друзья отправлен.")
    return redirect(url_for('find_friends'))

@app.route('/cancel_friend_request/<int:friend_id>', methods=['POST'])
@login_required
def cancel_friend_request(friend_id):
    friend_request = FriendRequest.query.filter_by(sender_id=current_user.id, recipient_id=friend_id, status='pending').first()
    if friend_request:
        db.session.delete(friend_request)
        db.session.commit()
        flash("Запрос отменен.")
    else:
        flash("Нет отправленной заявки для отмены.")
    return redirect(url_for('find_friends'))

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    if friend_request.recipient_id != current_user.id:
        flash("Недостаточно прав для принятия этого запроса.")
        return redirect(url_for('dashboard'))
    friend_request.status = 'accepted'
    sender = User.query.get(friend_request.sender_id)
    recipient = current_user
    sender.friends.append(recipient)
    recipient.friends.append(sender)
    db.session.commit()
    return redirect(url_for('friend_requests'))

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    if friend_request.recipient_id != current_user.id:
        flash("Недостаточно прав для отклонения этого запроса.")
        return redirect(url_for('dashboard'))
    friend_request.status = 'rejected'
    db.session.commit()
    return redirect(url_for('friend_requests'))

@app.route('/friend_requests')
@login_required
def friend_requests():
    requests_pending = FriendRequest.query.filter_by(recipient_id=current_user.id, status='pending').all()
    return render_template('friend_requests.html', requests=requests_pending)

# ===== Дополнительные маршруты =====

@app.route('/update_visibility', methods=['POST'])
@login_required
def update_visibility():
    visibility = request.form.get('visibility')
    if visibility not in ['none', 'all', 'friends']:
        flash("Неверное значение настройки видимости.")
    else:
        current_user.events_visibility = visibility
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/invite_friend/<int:event_id>/<int:friend_id>', methods=['POST'])
@login_required
def invite_friend(event_id, friend_id):
    friend = User.query.get_or_404(friend_id)
    event = Event.query.get_or_404(event_id)
    flash(f"Приглашение отправлено {friend.name} на мероприятие '{event.title}'.")
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    friend = User.query.get_or_404(friend_id)
    if friend not in current_user.friends.all():
        flash("Этот пользователь не в друзьях.")
    else:
        current_user.friends.remove(friend)
        friend.friends.remove(current_user)
        db.session.commit()
        flash(f"Пользователь {friend.name} удален из друзей.")
    return redirect(url_for('dashboard'))

# Новый маршрут для динамического поиска друзей (AJAX)
@app.route('/search_friends')
@login_required
def search_friends():
    query = request.args.get('q', '')
    users_query = User.query.filter(User.id != current_user.id, User.role=='participant')
    if query:
        search = f"%{query}%"
        users_query = users_query.filter(db.or_(User.name.ilike(search), User.email.ilike(search)))
    users = users_query.all()
    current_friend_ids = [f.id for f in current_user.friends.all()]
    available_users = [u for u in users if u.id not in current_friend_ids]
    data = [{'id': u.id, 'name': u.name, 'email': u.email} for u in available_users]
    return jsonify(data)

@app.route('/find_friends')
@login_required
def find_friends():
    return render_template('find_friends.html', q="")


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    # Проверяем, можно ли просматривать мероприятия
    can_view = False
    if current_user.id == user.id:
        can_view = True
    elif user.events_visibility == 'all':
        can_view = True
    elif user.events_visibility == 'friends' and (user in current_user.friends.all()):
        can_view = True

    events_data = []
    upcoming_events = []
    past_events = []
    if can_view:
        if user.role == 'organizer':
            # Для организатора — выбираем все его созданные мероприятия
            user_events = Event.query.filter_by(organizer_id=user.id).order_by(Event.event_date).all()
        else:
            # Для других пользователей – мероприятия, в которых они участвуют
            user_events = user.attended_events

        # Разбиваем мероприятия по времени
        upcoming_events = [event_to_dict(e) for e in user_events if is_event_active(e)]
        past_events = [event_to_dict(e) for e in user_events if not is_event_active(e)]
    return render_template('profile.html',
                           user=user,
                           upcoming_events=upcoming_events,
                           past_events=past_events)

# ===== Дополнительный маршрут для проверки статуса заявки в друзья =====
@app.route('/search_friend_request_status')
@login_required
def search_friend_request_status():
    recipient_id = request.args.get('recipient_id', type=int)
    if recipient_id is None:
        return jsonify({'pending': False})
    friend_request = FriendRequest.query.filter_by(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        status='pending'
    ).first()
    return jsonify({'pending': bool(friend_request)})

# ===== Функционал личного кабинета администратора =====

@app.route('/create_moderator', methods=['GET', 'POST'])
@login_required
def create_moderator():
    if current_user.role != 'administrator':
        flash("Доступ только для администраторов.")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует.')
            return redirect(url_for('create_moderator'))
        new_mod = User(email=email, name=name, role='moderator')
        new_mod.set_password(password)
        db.session.add(new_mod)
        db.session.commit()
        return redirect(url_for('administrator_dashboard'))
    return render_template('create_moderator.html')

# ===== Функционал редактирования данных (для модераторов и администраторов) =====

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.events_visibility = request.form.get('events_visibility')
        db.session.commit()
        dashboard_endpoint = 'administrator_dashboard' if current_user.role == 'administrator' else 'moderator_dashboard'
        return redirect(url_for(dashboard_endpoint))
    dashboard_endpoint = 'administrator_dashboard' if current_user.role == 'administrator' else 'moderator_dashboard'
    return render_template('edit_user.html', user=user, dashboard_endpoint=dashboard_endpoint)


@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    # Проверка прав доступа — только модераторы и администраторы
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))

    event = Event.query.get_or_404(event_id)

    if request.method == 'POST':
        # --- 1) Сохраняем простые поля ---
        event.title        = request.form['title']
        event.description  = request.form['description']
        event.location     = request.form['location']
        event.contacts     = request.form['contacts']
        event.event_format = request.form['event_format']
        event.category     = request.form['category']

        # Продолжительность
        dur = request.form.get('duration')
        event.duration = int(dur) if dur and dur.isdigit() else None

        # --- 2) Пытаемся геокодировать новый адрес, но не прерываем обработку при ошибках ---
        if event.location:
            try:
                yandex_api_key = "db080a73-5fc1-450e-9791-fddb3db87ac9"
                geocode_url = (
                    "https://geocode-maps.yandex.ru/1.x/"
                    f"?apikey={yandex_api_key}&format=json&results=1&lang=ru_RU&geocode="
                    + requests.utils.quote(event.location)
                )
                r = requests.get(geocode_url, timeout=5)
                r.raise_for_status()
                members = (
                    r.json()
                     .get("response", {})
                     .get("GeoObjectCollection", {})
                     .get("featureMember", [])
                )
                if members:
                    pos = members[0]["GeoObject"]["Point"]["pos"]
                    lon, lat = pos.split()
                    event.latitude  = float(lat)
                    event.longitude = float(lon)
                else:
                    flash("Координаты по новому адресу не найдены, но адрес сохранён.")
            except Exception as e:
                flash(f"Ошибка геокодирования (координаты не обновлены): {e}")

        # --- 3) Теги ---
        raw = request.form.get('selected_tags', '[]')
        try:
            names = json.loads(raw)
        except ValueError:
            names = []
        event.tags = []
        for n in names:
            tag = Tag.query.filter_by(name=n).first()
            if not tag:
                tag = Tag(name=n)
                db.session.add(tag)
                db.session.flush()
            event.tags.append(tag)

        # --- 4) Добавление новых файлов ---
        if 'new_files' in request.files:
            for f in request.files.getlist('new_files'):
                if f and allowed_file(f.filename):
                    ef = EventFile(
                        event_id=event.id,
                        file_data=f.read(),
                        mime_type=f.mimetype
                    )
                    db.session.add(ef)

        # --- 5) Сохраняем всё одной транзакцией ---
        db.session.commit()

        dst = 'administrator_dashboard' if current_user.role == 'administrator' else 'moderator_dashboard'
        return redirect(url_for(dst))

    # GET-запрос — готовим данные для формы
    all_tags      = [t.name for t in Tag.query.order_by(Tag.name).all()]
    selected_tags = [t.name for t in event.tags]
    return render_template(
        'edit_event.html',
        event=event,
        all_tags=all_tags,
        selected_tags=selected_tags
    )


@app.route('/delete_event_file/<int:file_id>', methods=['POST'])
@login_required
def delete_event_file(file_id):
    f = EventFile.query.get_or_404(file_id)
    # только модераторы/администраторы или владелец мероприятия
    if current_user.role not in ['moderator', 'administrator'] and current_user.id != f.event.organizer_id:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    event_id = f.event_id
    db.session.delete(f)
    db.session.commit()
    return redirect(url_for('edit_event', event_id=event_id))

# === Дополнительные маршруты для избранного тегов и организатора ===

@app.route('/add_favorite_tag/<string:tag_name>', methods=['POST'])
@login_required
def add_favorite_tag(tag_name):
    # Только участники могут добавлять в избранное
    if current_user.role != 'participant':
        return "Not allowed", 403
    tag_obj = Tag.query.filter_by(name=tag_name).first()
    if not tag_obj:
        return "Tag not found", 404
    if tag_obj not in current_user.favorite_tags:
        current_user.favorite_tags.append(tag_obj)
        db.session.commit()
    return "OK", 200

@app.route('/remove_favorite_tag/<string:tag_name>', methods=['POST'])
@login_required
def remove_favorite_tag(tag_name):
    if current_user.role != 'participant':
        return "Not allowed", 403
    tag_obj = Tag.query.filter_by(name=tag_name).first()
    if not tag_obj:
        return "Tag not found", 404
    if tag_obj in current_user.favorite_tags:
        current_user.favorite_tags.remove(tag_obj)
        db.session.commit()
    return "OK", 200

@app.route('/add_favorite_organizer/<int:organizer_id>', methods=['POST'])
@login_required
def add_favorite_organizer(organizer_id):
    if current_user.role != 'participant':
        return "Not allowed", 403
    organizer = User.query.get_or_404(organizer_id)
    if organizer not in current_user.favorite_organizers:
        current_user.favorite_organizers.append(organizer)
        db.session.commit()
    return "OK", 200

@app.route('/remove_favorite_organizer/<int:organizer_id>', methods=['POST'])
@login_required
def remove_favorite_organizer(organizer_id):
    if current_user.role != 'participant':
        return "Not allowed", 403
    organizer = User.query.get_or_404(organizer_id)
    if organizer in current_user.favorite_organizers:
        current_user.favorite_organizers.remove(organizer)
        db.session.commit()
    return "OK", 200

@app.route('/invite_event/<int:event_id>/<int:friend_id>', methods=['POST'])
@login_required
def invite_event(event_id, friend_id):
    friend = User.query.get_or_404(friend_id)
    event = Event.query.get_or_404(event_id)

    # Если выбранный друг уже записан на мероприятие, возвращаем ошибку
    if friend in event.attendees:
        return jsonify({"error": "Пользователь уже записан на мероприятие"}), 403

    # Проверяем, существует ли уже приглашение от текущего пользователя для этого друга
    invitation = EventInvitation.query.filter_by(
        event_id=event_id,
        inviter_id=current_user.id,  # используем inviter_id, как указано в модели
        invitee_id=friend_id         # используем invitee_id
    ).first()

    if invitation:
        if invitation.status == 'pending':
            # Если приглашение уже отправлено и в состоянии pending – отменяем его
            db.session.delete(invitation)
            db.session.commit()
            return jsonify({"status": "cancelled"})
        else:
            # Если приглашение уже обработано, возвращаем его статус
            return jsonify({"status": invitation.status})
    else:
        # Создаем новое приглашение, если его нет
        invitation = EventInvitation(
            event_id=event_id,
            inviter_id=current_user.id,
            invitee_id=friend_id,
            status="pending"
        )
        db.session.add(invitation)
        db.session.commit()
        return jsonify({"status": "pending"})

@app.route('/check_invitation/<int:event_id>/<int:friend_id>')
@login_required
def check_invitation(event_id, friend_id):
    invitation = EventInvitation.query.filter_by(
        event_id=event_id,
        inviter_id=current_user.id,
        invitee_id=friend_id
    ).first()
    if invitation:
        return jsonify({"status": invitation.status})
    else:
        return jsonify({"status": "none"})

@app.route('/accept_invitation/<int:invitation_id>', methods=['POST'])
@login_required
def accept_invitation(invitation_id):
    invitation = EventInvitation.query.get_or_404(invitation_id)
    # Проверяем, что текущий пользователь действительно invitee
    if invitation.invitee_id != current_user.id:
        flash("Невозможно принять это приглашение.")
        return redirect(url_for('profile', user_id=current_user.id))
    invitation.status = 'accepted'
    # Если пользователь ещё не записан на мероприятие — записываем
    event = Event.query.get(invitation.event_id)
    if event and event not in current_user.attended_events:
        current_user.attended_events.append(event)
    db.session.commit()
    flash("Приглашение принято. Вы записаны на мероприятие.")
    return redirect(url_for('dashboard', user_id=current_user.id))

@app.route('/reject_invitation/<int:invitation_id>', methods=['POST'])
@login_required
def reject_invitation(invitation_id):
    invitation = EventInvitation.query.get_or_404(invitation_id)
    if invitation.invitee_id != current_user.id:
        flash("Невозможно отклонить это приглашение.")
        return redirect(url_for('profile', user_id=current_user.id))
    invitation.status = 'rejected'
    db.session.commit()
    flash("Приглашение отклонено.")
    return redirect(url_for('dashboard', user_id=current_user.id))

@app.route('/my_invitations')
@login_required
def my_invitations():
    # Так как в БД inviter_id и invitee_id, здесь ищем по invitee_id
    invitations = EventInvitation.query.filter_by(
        invitee_id=current_user.id,
        status='pending'
    ).all()
    return render_template('my_invitations.html', invitations=invitations)


# Аналогично в API: фильтруем события
@app.route('/api/events')
def api_events():
    current_category = request.args.get('category', 'Все')
    favorites_filter = request.args.get('favorites', '0')
    query = Event.query.order_by(Event.event_date)
    if current_category and current_category != 'Все':
        query = query.filter(Event.category == current_category)
    events = query.all()

    events = [e for e in events if is_event_active(e)]

    if favorites_filter == '1' and current_user.is_authenticated and current_user.role == 'participant':
        filtered_events = []
        for e in events:
            is_fav = any(tag in current_user.favorite_tags for tag in e.tags) or (
                        e.organizer in current_user.favorite_organizers)
            if is_fav:
                filtered_events.append(e)
        events = filtered_events

    events_data = [event_to_dict(e) for e in events]
    return jsonify(events_data)

@app.route('/accreditation_applications')
@login_required
def accreditation_applications():
    # Только модераторы и администраторы имеют доступ
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    applications = AccreditationApplication.query.filter_by(status='pending').all()
    return render_template('accreditation_applications.html', applications=applications)

@app.route('/accreditation_requests')
@login_required
def accreditation_requests():
    # Доступ только для модераторов и администраторов
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    # Получаем все заявки со статусом 'pending'
    applications = AccreditationApplication.query.filter_by(status='pending').all()
    return render_template('accreditation_requests.html', applications=applications)

@app.route('/accreditation_requests/<int:application_id>/accept', methods=['POST'])
@login_required
def accept_accreditation(application_id):
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    app_entry = AccreditationApplication.query.get_or_404(application_id)
    app_entry.status = 'accepted'
    # Обновляем статус пользователя
    app_entry.user.accreditation_status = 'accepted'
    db.session.commit()
    return redirect(url_for('accreditation_requests'))

@app.route('/accreditation_requests/<int:application_id>/reject', methods=['POST'])
@login_required
def reject_accreditation(application_id):
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    reason = request.form.get('reason')
    app_entry = AccreditationApplication.query.get_or_404(application_id)
    app_entry.status = 'rejected'
    app_entry.moderator_reason = reason
    # Обновляем статус пользователя
    user = app_entry.user
    user.accreditation_status = 'rejected'
    user.accreditation_rejection_reason = reason
    db.session.commit()
    return redirect(url_for('accreditation_requests'))


@app.route('/apply_accreditation', methods=['GET', 'POST'])
@login_required
def apply_accreditation():
    if current_user.role != 'organizer':
        flash("Доступно только для организаторов.")
        return redirect(url_for('dashboard'))
    if current_user.accreditation_status in ['pending', 'accepted']:
        flash("Вы уже подали заявку или уже аккредитованы.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        person_type = request.form.get('person_type')
        # Поля общие для всех заявок:
        full_name = request.form.get('full_name')
        date_of_birth = request.form.get('date_of_birth')  # преобразование в datetime.date ниже
        registration_address = request.form.get('registration_address')
        phone = request.form.get('phone')
        contact_email = request.form.get('contact_email')
        resume = request.form.get('resume')
        # Для юридических лиц:
        organization_name = request.form.get('organization_name')
        legal_address = request.form.get('legal_address')
        actual_address = request.form.get('actual_address')
        ceo_name = request.form.get('ceo_name')
        website = request.form.get('website')
        social_links = request.form.get('social_links')
        company_description = request.form.get('company_description')

        # Обработка файлов для физических лиц:
        passport_file = request.files.get('passport_copy')
        if person_type == 'physical' and passport_file:
            passport_copy_data = passport_file.read()
            passport_copy_filename = secure_filename(passport_file.filename)
        else:
            passport_copy_data = None
            passport_copy_filename = None

        ind_reg_file = request.files.get('individual_reg_doc')
        if person_type == 'physical' and ind_reg_file:
            individual_reg_doc_data = ind_reg_file.read()
            individual_reg_doc_filename = secure_filename(ind_reg_file.filename)
        else:
            individual_reg_doc_data = None
            individual_reg_doc_filename = None

        # Обработка файлов для юридических лиц:
        egrul_file = request.files.get('egrul_extract')
        if person_type == 'legal' and egrul_file:
            egrul_extract_data = egrul_file.read()
            egrul_extract_filename = secure_filename(egrul_file.filename)
        else:
            egrul_extract_data = None
            egrul_extract_filename = None

        tax_file = request.files.get('tax_certificate')
        if person_type == 'legal' and tax_file:
            tax_certificate_data = tax_file.read()
            tax_certificate_filename = secure_filename(tax_file.filename)
        else:
            tax_certificate_data = None
            tax_certificate_filename = None

        license_file = request.files.get('license_doc')
        if person_type == 'legal' and license_file:
            license_doc_data = license_file.read()
            license_doc_filename = secure_filename(license_file.filename)
        else:
            license_doc_data = None
            license_doc_filename = None

        exp_file = request.files.get('experience_docs')
        if exp_file:
            experience_docs_data = exp_file.read()
            experience_docs_filename = secure_filename(exp_file.filename)
        else:
            experience_docs_data = None
            experience_docs_filename = None

        consent = True if request.form.get('consent') else False
        if not consent:
            flash("Требуется согласие на проверку документов.")
            return redirect(url_for('apply_accreditation'))

        try:
            dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date() if date_of_birth else None
        except ValueError:
            flash("Неверный формат даты рождения.")
            return redirect(url_for('apply_accreditation'))

        # Создаем новый объект заявки
        new_app = AccreditationApplication(
            user_id=current_user.id,
            person_type=person_type,
            full_name=full_name,
            date_of_birth=dob,
            registration_address=registration_address,
            phone=phone,
            resume=resume,
            organization_name=organization_name,
            legal_address=legal_address,
            actual_address=actual_address,
            ceo_name=ceo_name,
            website=website,
            social_links=social_links,
            company_description=company_description,
            passport_copy=passport_copy_data,
            individual_registration_doc=individual_reg_doc_data,
            egrul_extract=egrul_extract_data,
            tax_certificate=tax_certificate_data,
            license_doc=license_doc_data,
            professional_experience_docs=experience_docs_data,
            # Сохраняем исходные имена файлов:
            passport_copy_filename=passport_copy_filename,
            individual_registration_doc_filename=individual_reg_doc_filename,
            egrul_extract_filename=egrul_extract_filename,
            tax_certificate_filename=tax_certificate_filename,
            license_doc_filename=license_doc_filename,
            professional_experience_docs_filename=experience_docs_filename,
            consent=consent,
            status='pending'
        )
        db.session.add(new_app)
        current_user.accreditation_status = 'pending'
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('accreditation_application.html')


@app.route('/accreditation_application/<int:application_id>')
@login_required
def view_accreditation_application(application_id):
    # Только модераторы и администраторы могут просматривать подробности заявки
    if current_user.role not in ['moderator', 'administrator']:
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    app_entry = AccreditationApplication.query.get_or_404(application_id)
    return render_template('accreditation_application_detail.html', application=app_entry)


@app.route('/accreditation_file/<int:application_id>/<string:file_field>')
@login_required
def accreditation_file(application_id, file_field):
    # Допустимые имена полей с бинарными данными
    allowed_fields = {
        'passport_copy',
        'individual_registration_doc',
        'egrul_extract',
        'tax_certificate',
        'license_doc',
        'professional_experience_docs'
    }
    if file_field not in allowed_fields:
        flash("Неверный тип файла.")
        return redirect(url_for('view_accreditation_application', application_id=application_id))

    app_entry = AccreditationApplication.query.get_or_404(application_id)
    data = getattr(app_entry, file_field)
    if not data:
        flash("Запрошенный файл не найден.")
        return redirect(url_for('view_accreditation_application', application_id=application_id))

    # Получаем сохранённое имя файла (например, passport_copy_filename)
    filename_field = f"{file_field}_filename"
    original_filename = getattr(app_entry, filename_field, None)
    if not original_filename:
        # Если не сохранено – определяем расширение по умолчанию
        default_extensions = {
            'passport_copy': '.jpg',
            'individual_registration_doc': '.pdf',
            'egrul_extract': '.pdf',
            'tax_certificate': '.pdf',
            'license_doc': '.pdf',
            'professional_experience_docs': '.pdf'
        }
        ext = default_extensions.get(file_field, '.bin')
        original_filename = f"{file_field}{ext}"

    # Определяем MIME‑тип исходя из имени файла
    mime_type, _ = mimetypes.guess_type(original_filename)
    if not mime_type:
        mime_type = 'application/octet-stream'

    return Response(
        data,
        mimetype=mime_type,
        headers={"Content-Disposition": f"attachment; filename={original_filename}"}
    )

@app.route('/update_organizer_info', methods=['POST'])
@login_required
def update_organizer_info():
    if current_user.role != 'organizer':
        flash("Доступ запрещён.")
        return redirect(url_for('dashboard'))
    # НЕ обновляем organization_name
    # current_user.organization_name = request.form.get('organization_name')  <-- удалили или закомментировали эту строку
    current_user.description = request.form.get('description')
    current_user.activity_field = request.form.get('activity_field')
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    avatar = request.form.get('avatar')
    # проверяем, что файл есть в списке разрешённых
    valid = {
      'participant_avatar_none.png',
      'participant_avatar_man_1.png',
      'participant_avatar_man_2.png',
      'participant_avatar_man_3.png',
      'participant_avatar_woman_1.png',
      'participant_avatar_woman_2.png',
      'participant_avatar_woman_3.png'
    }
    if avatar in valid:
        current_user.avatar_filename = avatar
        db.session.commit()
    else:
        flash('Неверный выбор аватара.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/create_tag', methods=['POST'])
@login_required
def create_tag():
    data = request.get_json(silent=True) or {}
    name = data.get('name','').strip()
    if not name:
        return jsonify(success=False, message="Введите имя тега"), 400

    # Поиск в нижнем регистре
    existing = Tag.query.filter(func.lower(Tag.name) == name.lower()).first()
    if existing:
        return jsonify(success=False, message="Тег уже существует"), 400

    tag = Tag(name=name)
    db.session.add(tag)
    db.session.commit()

    return jsonify(success=True, tag={'id': tag.id, 'name': tag.name})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)