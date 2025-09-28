import os
import datetime
import json
import base64
import re
from email.mime.text import MIMEText
from email.utils import parseaddr

import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from functools import wraps

# THIS IS A WORKAROUND FOR DEVELOPMENT/PROXY ISSUES.
if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# ===================================================================
# 1. הגדרת טפסים (Forms)
# ===================================================================

class RegistrationForm(FlaskForm):
    email = StringField('אימייל', validators=[DataRequired(), Email(message='אנא הזן כתובת אימייל תקינה.')])
    password = PasswordField('סיסמה', validators=[DataRequired()])
    confirm_password = PasswordField('אימות סיסמה', validators=[DataRequired(), EqualTo('password', message='הסיסמאות חייבות להיות זהות')])
    submit = SubmitField('הרשמה')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('כתובת אימייל זו כבר תפוסה.')

class LoginForm(FlaskForm):
    email = StringField('אימייל', validators=[DataRequired(), Email()])
    password = PasswordField('סיסמה', validators=[DataRequired()])
    submit = SubmitField('כניסה')

class EmailForm(FlaskForm):
    subject = StringField('נושא', validators=[DataRequired()])
    body = TextAreaField('תוכן ההודעה', validators=[DataRequired()])
    submit = SubmitField('שלח מייל')

# ===================================================================
# 2. הגדרת האפליקציה והרחבות
# ===================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_secret_key_for_development_change_me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///crm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_RECYCLE'] = 280
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20

metadata = MetaData(naming_convention={
    "ix": 'ix_%(column_0_label)s', "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s", "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "אנא התחבר כדי לגשת לעמוד זה."
login_manager.login_message_category = 'info'

@app.template_filter('nl2br')
def nl2br(s):
    return s.replace('\n', '<br>')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ===================================================================
# 3. הגדרת מודלים (Database Models)
# ===================================================================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    gmail_credentials_json = db.Column(db.Text, nullable=True)

class ContactType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    statuses = db.relationship('Status', backref='contact_type', lazy=True, cascade="all, delete-orphan")

class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'), nullable=False)

class ActivityType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'))
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'))
    contact_type = db.relationship('ContactType', backref='contacts')
    status = db.relationship('Status', backref='contacts')
    activities = db.relationship('Activity', backref='contact', lazy=True, cascade="all, delete-orphan")

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)
    activity_type_id = db.Column(db.Integer, db.ForeignKey('activity_type.id'))
    activity_type = db.relationship('ActivityType', backref='activities')
    gmail_message_id = db.Column(db.String(100), unique=True, nullable=True)

class SavedView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    filters = db.Column(db.JSON, nullable=False)

class CustomField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    field_type = db.Column(db.String(50), default='text')
    api_identifier = db.Column(db.String(100), unique=True, nullable=False)

class CustomFieldValue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Text, nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id', ondelete='CASCADE'), nullable=False)
    field_id = db.Column(db.Integer, db.ForeignKey('custom_field.id', ondelete='CASCADE'), nullable=False)
    contact = db.relationship('Contact', backref=db.backref('custom_values', cascade="all, delete-orphan"))
    field = db.relationship('CustomField')

# ===================================================================
# 4. פונקציות עזר (Helper Functions)
# ===================================================================

def get_gmail_service(user):
    if not user.gmail_credentials_json:
        return None
    try:
        creds_info = json.loads(user.gmail_credentials_json)
        credentials = google.oauth2.credentials.Credentials.from_authorized_user_info(creds_info)
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except Exception as e:
        print(f"Error creating Gmail service for user {user.email}: {e}")
        return None

def _parse_email_parts(parts):
    body = ""
    if parts:
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                body += base64.urlsafe_b64decode(part.get('body').get('data', '')).decode('utf-8', 'ignore')
            elif 'parts' in part:
                body += _parse_email_parts(part.get('parts'))
    return body

# ===================================================================
# 5. נתיבים (Routes)
# ===================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password_hash=hashed_password)
        if not User.query.first():
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('החשבון נוצר בהצלחה!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('התחברות נכשלה. אנא בדוק אימייל וסיסמה.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    query = Contact.query
    contact_type_filter, status_filter, sort_by = None, [], 'created_at_desc'
    view_id = request.args.get('view_id', type=int)
    if view_id:
        view = SavedView.query.get(view_id)
        if view:
            filters = view.filters
            contact_type_filter = filters.get('contact_type_id')
            status_filter = filters.get('status_id', [])
            sort_by = filters.get('sort_by', 'created_at_desc')
    else:
        contact_type_filter = request.args.get('contact_type_id', type=int)
        status_filter = request.args.getlist('status_id', type=int)
        sort_by = request.args.get('sort_by', 'created_at_desc')

    if contact_type_filter: query = query.filter(Contact.contact_type_id == contact_type_filter)
    if status_filter: query = query.filter(Contact.status_id.in_(status_filter))

    sort_map = {'created_at_asc': Contact.created_at.asc(), 'updated_at_desc': Contact.updated_at.desc(), 'updated_at_asc': Contact.updated_at.asc()}
    query = query.order_by(sort_map.get(sort_by, Contact.created_at.desc()))

    contacts = query.all()
    contact_types = ContactType.query.all()
    all_statuses = Status.query.all()
    saved_views = SavedView.query.order_by(SavedView.name).all()
    
    # --- התיקון כאן: שליחת משתנים באופן מפורש במקום **locals() ---
    return render_template('index.html',
                           contacts=contacts,
                           contact_types=contact_types,
                           all_statuses=all_statuses,
                           saved_views=saved_views,
                           active_type_filter=contact_type_filter,
                           active_status_filter=status_filter,
                           active_sort=sort_by)

@app.route('/communications')
@login_required
def communications():
    all_activities = db.session.query(Activity, Contact).join(Contact).order_by(Activity.timestamp.desc()).all()
    return render_template('communications.html', all_activities=all_activities)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        new_contact = Contact(name=request.form['name'], email=request.form['email'], phone=request.form['phone'])
        db.session.add(new_contact)
        db.session.commit()
        flash('איש הקשר נוסף בהצלחה!', 'success')
        return redirect(url_for('index'))
    return render_template('add_contact.html')

@app.route('/contact/<int:contact_id>')
@login_required
def contact_detail(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    activities = Activity.query.filter_by(contact_id=contact.id).order_by(Activity.timestamp.desc()).all()
    contact_types = ContactType.query.all()
    statuses = Status.query.all()
    activity_types = ActivityType.query.all()
    custom_fields = CustomField.query.order_by(CustomField.name).all()
    contact_custom_values = {val.field_id: val.value for val in contact.custom_values}
    email_form = EmailForm()
    
    # --- שיפור: שליחת משתנים באופן מפורש במקום **locals() ---
    return render_template('contact_detail.html',
                           contact=contact,
                           activities=activities,
                           contact_types=contact_types,
                           statuses=statuses,
                           activity_types=activity_types,
                           custom_fields=custom_fields,
                           contact_custom_values=contact_custom_values,
                           email_form=email_form)

@app.route('/contact/<int:contact_id>/edit', methods=['POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    contact.name = request.form.get('name')
    contact.email = request.form.get('email')
    contact.phone = request.form.get('phone')
    contact.contact_type_id = request.form.get('contact_type_id', type=int) or None
    contact.status_id = request.form.get('status_id', type=int) or None
    
    for field in CustomField.query.all():
        value_str = request.form.get(f'custom_{field.id}')
        existing_value = CustomFieldValue.query.filter_by(contact_id=contact.id, field_id=field.id).first()
        if value_str:
            if existing_value: existing_value.value = value_str
            else: db.session.add(CustomFieldValue(value=value_str, contact_id=contact.id, field_id=field.id))
        elif existing_value: db.session.delete(existing_value)
            
    db.session.commit()
    flash('פרטי איש הקשר עודכנו בהצלחה!', 'success')
    return redirect(url_for('contact_detail', contact_id=contact_id))

@app.route('/contact/<int:contact_id>/add_activity', methods=['POST'])
@login_required
def add_activity(contact_id):
    if request.form['description']:
        new_activity = Activity(description=request.form['description'], contact_id=contact_id, activity_type_id=request.form.get('activity_type_id', type=int))
        db.session.add(new_activity)
        db.session.commit()
    return redirect(url_for('contact_detail', contact_id=contact_id))

@app.route('/contact/<int:contact_id>/send_email', methods=['POST'])
@login_required
def send_email(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    form = EmailForm()

    if form.validate_on_submit():
        if not contact.email:
            flash('לאיש קשר זה אין כתובת אימייל.', 'warning')
        else:
            service = get_gmail_service(current_user)
            if not service:
                flash('חשבון Gmail אינו מחובר או שהחיבור אינו תקין.', 'danger')
            else:
                try:
                    message = MIMEText(form.body.data)
                    message['to'] = contact.email
                    message['from'] = 'me'
                    message['subject'] = form.subject.data
                    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                    create_message = {'raw': encoded_message}
                    
                    service.users().messages().send(userId="me", body=create_message).execute()
                    
                    activity_description = f"מייל נשלח ל-{contact.email}\nנושא: {form.subject.data}\n\n{form.body.data}"
                    activity = Activity(description=activity_description, contact_id=contact_id, source="Email Sent")
                    db.session.add(activity)
                    db.session.commit()

                    flash(f'המייל ל-{contact.email} נשלח בהצלחה!', 'success')
                except Exception as e:
                    flash(f'שגיאה בשליחת המייל: {e}', 'danger')

    return redirect(url_for('contact_detail', contact_id=contact_id))

@app.route('/contact/<int:contact_id>/sync_gmail')
@login_required
def sync_gmail(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    if not contact.email:
        flash('לא ניתן לסנכרן מיילים, לאיש קשר זה אין כתובת מייל.', 'warning')
        return redirect(url_for('contact_detail', contact_id=contact.id))

    service = get_gmail_service(current_user)
    if not service:
        flash('חשבון Gmail אינו מחובר.', 'danger')
        return redirect(url_for('contact_detail', contact_id=contact.id))

    try:
        query = f'from:{contact.email}'
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        
        if not messages:
            flash('לא נמצאו מיילים חדשים מאיש קשר זה.', 'info')
            return redirect(url_for('contact_detail', contact_id=contact.id))

        new_emails_count = 0
        for msg in messages:
            msg_id = msg['id']
            if Activity.query.filter_by(gmail_message_id=msg_id).first():
                continue

            message_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            payload = message_data.get('payload', {})
            headers = payload.get('headers', [])
            
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'ללא נושא')
            from_email = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
            
            body = ""
            if 'parts' in payload:
                body = _parse_email_parts(payload['parts'])
            elif payload.get('body', {}).get('data'):
                body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', 'ignore')

            activity_description = f"מייל שהתקבל מ-{from_email}\nנושא: {subject}\n\n{body}"
            activity = Activity(description=activity_description, contact_id=contact_id, source="Gmail Sync", gmail_message_id=msg_id)
            db.session.add(activity)
            new_emails_count += 1
        
        if new_emails_count > 0:
            db.session.commit()
            flash(f'סונכרנו {new_emails_count} מיילים חדשים בהצלחה!', 'success')
        else:
            flash('לא נמצאו מיילים חדשים מאיש קשר זה.', 'info')

    except Exception as e:
        flash(f'שגיאה בסנכרון המיילים: {e}', 'danger')

    return redirect(url_for('contact_detail', contact_id=contact.id))

@app.route('/settings')
@login_required
@admin_required
def settings():
    contact_types = ContactType.query.order_by(ContactType.name).all()
    activity_types = ActivityType.query.order_by(ActivityType.name).all()
    custom_fields = CustomField.query.order_by(CustomField.name).all()
    # --- שיפור: שליחת משתנים באופן מפורש במקום **locals() ---
    return render_template('settings.html',
                           contact_types=contact_types,
                           activity_types=activity_types,
                           custom_fields=custom_fields)

@app.route('/settings/add_contact_type', methods=['POST'])
@login_required
@admin_required
def add_contact_type():
    if request.form.get('name'):
        db.session.add(ContactType(name=request.form.get('name')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/add_status', methods=['POST'])
@login_required
@admin_required
def add_status():
    if request.form.get('name') and request.form.get('contact_type_id'):
        db.session.add(Status(name=request.form.get('name'), contact_type_id=request.form.get('contact_type_id')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/add_activity_type', methods=['POST'])
@login_required
@admin_required
def add_activity_type():
    if request.form.get('name'):
        db.session.add(ActivityType(name=request.form.get('name')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/edit/<item_type>/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def edit_setting(item_type, item_id):
    if request.form.get('name'):
        model = {'contact_type': ContactType, 'status': Status, 'activity_type': ActivityType}.get(item_type)
        if model:
            item = model.query.get_or_404(item_id)
            item.name = request.form.get('name')
            db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/delete/<item_type>/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def delete_setting(item_type, item_id):
    model_map = {'contact_type': ContactType, 'status': Status, 'activity_type': ActivityType, 'saved_view': SavedView}
    model = model_map.get(item_type)
    if model:
        item = model.query.get_or_404(item_id)
        if item_type in ['contact_type', 'status'] and item.contacts:
            flash(f"לא ניתן למחוק את '{item.name}' מכיוון שיש ישויות המשויכות אליו.", "danger")
            return redirect(url_for('settings'))
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('index') if item_type == 'saved_view' else url_for('settings'))

@app.route('/settings/add_custom_field', methods=['POST'])
@login_required
@admin_required
def add_custom_field():
    name = request.form.get('name')
    if name:
        temp_identifier = name.lower()
        temp_identifier = re.sub(r'\s+', '_', temp_identifier)
        api_id = 'custom_' + re.sub(r'[^a-zA-Z0-9_]', '', temp_identifier)
        if CustomField.query.filter_by(api_identifier=api_id).first():
            flash(f"שדה עם מזהה API דומה ('{api_id}') כבר קיים. אנא בחר שם אחר.", "danger")
        else:
            new_field = CustomField(name=name, api_identifier=api_id)
            db.session.add(new_field)
            db.session.commit()
            flash("השדה המותאם נוצר בהצלחה!", "success")
    return redirect(url_for('settings'))

@app.route('/settings/edit/custom_field/<int:field_id>', methods=['POST'])
@login_required
@admin_required
def edit_custom_field(field_id):
    if request.form.get('name'):
        field = CustomField.query.get_or_404(field_id)
        field.name = request.form.get('name')
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/delete/custom_field/<int:field_id>', methods=['POST'])
@login_required
@admin_required
def delete_custom_field(field_id):
    field = CustomField.query.get_or_404(field_id)
    db.session.delete(field)
    db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.email).all()
    return render_template('manage_users.html', users=users)

@app.route('/settings/users/set_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def set_user_admin_status(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f'הרשאות המשתמש {user.email} עודכנו.', 'success')
    else:
        flash('אינך יכול לשנות את ההרשאות של עצמך.', 'warning')
    return redirect(url_for('manage_users'))

@app.route('/settings/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete == current_user:
        flash('אינך יכול למחוק את המשתמש של עצמך.', 'danger')
    elif user_to_delete.is_admin and User.query.filter_by(is_admin=True).count() == 1:
        flash('אינך יכול למחוק את המנהל האחרון במערכת.', 'danger')
    else:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'המשתמש {user_to_delete.email} נמחק בהצלחה.', 'success')
    return redirect(url_for('manage_users'))

def create_client_secret_file():
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    if client_id and client_secret:
        client_config = { "web": {
            "client_id": client_id, "project_id": "y-crm-integration",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret
        }}
        with open('client_secret.json', 'w') as f: json.dump(client_config, f)
        return True
    return False

@app.before_request
def before_request_func():
    if not os.path.exists('client_secret.json'):
        create_client_secret_file()

@app.route('/settings/gmail/authorize')
@login_required
def authorize_gmail():
    if not os.path.exists('client_secret.json'):
        flash('שירות אינטגרציית Gmail אינו מוגדר.', 'warning')
        return redirect(url_for('settings'))
        
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify'],
        redirect_uri=url_for('oauth2callback', _external=True, _scheme='https')
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    state = session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json', scopes=None, state=state,
        redirect_uri=url_for('oauth2callback', _external=True, _scheme='https')
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    current_user.gmail_credentials_json = credentials.to_json()
    db.session.commit()
    flash('חשבון Gmail חובר בהצלחה!', 'success')
    return redirect(url_for('settings'))

@app.route('/api/save_view', methods=['POST'])
@login_required
def save_view():
    data = request.get_json()
    if not data or not data.get('name') or data.get('filters') is None:
        return jsonify({'success': False, 'message': 'Missing data'}), 400
    view = SavedView(name=data['name'], filters=data['filters'])
    db.session.add(view)
    db.session.commit()
    return jsonify({'success': True, 'message': 'View saved!'})
    
@app.route('/api/lead', methods=['POST'])
def handle_lead():
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid request. Expecting JSON data."}), 400
    email, phone = data.get('email'), data.get('phone')
    if not email and not phone: return jsonify({"error": "Either email or phone is required."}), 400
    contact = None
    if email: contact = Contact.query.filter_by(email=email).first()
    if not contact and phone: contact = Contact.query.filter_by(phone=phone).first()
    if not contact:
        name = data.get('name') or email or phone
        contact = Contact(name=name, email=email, phone=phone)
        db.session.add(contact)
        db.session.flush() # Ensure contact has an ID before creating activity
    activity_description = f"פנייה חדשה ממקור: {data.get('source', 'לא ידוע')}\n{data.get('message', '')}"
    new_activity = Activity(description=activity_description, source=data.get('source', 'לא ידוע'), contact_id=contact.id)
    db.session.add(new_activity)
    db.session.commit()
    return jsonify({"success": True, "message": "Lead processed successfully.", "contact_id": contact.id}), 201

def run_full_gmail_sync():
    with app.app_context():
        users_with_gmail = User.query.filter(User.gmail_credentials_json.isnot(None)).all()
        print(f"מתחיל סנכרון רקע. נמצאו {len(users_with_gmail)} משתמשים עם חיבור Gmail.")

        for user in users_with_gmail:
            service = get_gmail_service(user)
            if not service:
                print(f"שגיאה ביצירת שירות Gmail עבור {user.email}. מדלג.")
                continue

            try:
                results = service.users().messages().list(userId='me', q='is:unread in:inbox').execute()
                messages = results.get('messages', [])
                
                if not messages:
                    print(f"לא נמצאו מיילים חדשים עבור {user.email}.")
                    continue
                
                print(f"נמצאו {len(messages)} מיילים חדשים עבור {user.email}.")

                for msg in messages:
                    msg_id = msg['id']
                    
                    if Activity.query.filter_by(gmail_message_id=msg_id).first():
                        continue

                    message_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
                    payload = message_data.get('payload', {})
                    headers = payload.get('headers', [])
                    
                    from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
                    sender_name, sender_email = parseaddr(from_header)

                    if not sender_email: continue

                    contact = Contact.query.filter_by(email=sender_email).first()

                    if not contact:
                        contact = Contact(name=sender_name or sender_email, email=sender_email)
                        db.session.add(contact)
                        db.session.flush()
                        print(f"נוצר איש קשר חדש: {contact.name} ({contact.email})")

                    subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'ללא נושא')
                    body = ""
                    if 'parts' in payload:
                        body = _parse_email_parts(payload['parts'])
                    elif payload.get('body', {}).get('data'):
                        body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', 'ignore')

                    activity_description = f"מייל שהתקבל מ-{sender_email}\nנושא: {subject}\n\n{body}"
                    activity = Activity(
                        description=activity_description, 
                        contact_id=contact.id, 
                        source="Gmail Sync (Auto)",
                        gmail_message_id=msg_id
                    )
                    db.session.add(activity)
                    print(f"נוספה פעילות חדשה לאיש הקשר {contact.name}")

                    service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()

                db.session.commit()

            except Exception as e:
                print(f"שגיאה קריטית בסנכרון עבור {user.email}: {e}")
                db.session.rollback()