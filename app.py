import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData, or_

# 1. הגדרת האפליקציה ומסד הנתונים
app = Flask(__name__)
database_url = os.environ.get('DATABASE_URL') or 'sqlite:///crm.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)
db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# 2. הגדרת מודלים
class ContactType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    statuses = db.relationship('Status', backref='contact_type', lazy=True, cascade="all, delete-orphan")
    def __repr__(self): return self.name

class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'), nullable=False)
    def __repr__(self): return self.name

class ActivityType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    def __repr__(self): return self.name

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'), nullable=True)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=True)
    contact_type = db.relationship('ContactType', backref='contacts')
    status = db.relationship('Status', backref='contacts')
    activities = db.relationship('Activity', backref='contact', lazy=True, cascade="all, delete-orphan")
    def __repr__(self): return f'<Contact {self.name}>'

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)
    activity_type_id = db.Column(db.Integer, db.ForeignKey('activity_type.id'), nullable=True)
    activity_type = db.relationship('ActivityType', backref='activities')
    def __repr__(self): return f'<Activity {self.id}>'

class SavedView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    filters = db.Column(db.JSON, nullable=False)
    def __repr__(self): return self.name

# 3. הגדרת נתיבים (Routes)
@app.route('/')
def index():
    query = Contact.query
    contact_type_filter, status_filter, sort_by = None, [], 'created_at_desc'
    view_id = request.args.get('view_id', type=int)
    if view_id:
        view = SavedView.query.get(view_id)
        if view:
            filters = view.filters
            contact_type_filter, status_filter, sort_by = filters.get('contact_type_id'), filters.get('status_id', []), filters.get('sort_by', 'created_at_desc')
    else:
        contact_type_filter, status_filter, sort_by = request.args.get('contact_type_id', type=int), request.args.getlist('status_id', type=int), request.args.get('sort_by', 'created_at_desc')

    if contact_type_filter: query = query.filter(Contact.contact_type_id == contact_type_filter)
    if status_filter: query = query.filter(Contact.status_id.in_(status_filter))

    sort_map = {'created_at_asc': Contact.created_at.asc(), 'updated_at_desc': Contact.updated_at.desc(), 'updated_at_asc': Contact.updated_at.asc()}
    query = query.order_by(sort_map.get(sort_by, Contact.created_at.desc()))
    
    contacts = query.all()
    contact_types, all_statuses, saved_views = ContactType.query.all(), Status.query.all(), SavedView.query.order_by(SavedView.name).all()
    
    return render_template('index.html', **locals())

# --- !!! הנה הפונקציה שהוחזרה !!! ---
@app.route('/add', methods=['GET', 'POST'])
def add_contact():
    """דף להוספת איש קשר חדש"""
    if request.method == 'POST':
        new_contact = Contact(
            name=request.form['name'],
            email=request.form['email'],
            phone=request.form['phone']
        )
        db.session.add(new_contact)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_contact.html')
# --------------------------------------

@app.route('/contact/<int:contact_id>')
def contact_detail(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    activities = Activity.query.filter_by(contact_id=contact.id).order_by(Activity.timestamp.desc()).all()
    contact_types, statuses, activity_types = ContactType.query.all(), Status.query.all(), ActivityType.query.all()
    return render_template('contact_detail.html', **locals())

@app.route('/contact/<int:contact_id>/edit', methods=['POST'])
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    contact.name = request.form.get('name')
    contact.email = request.form.get('email')
    contact.phone = request.form.get('phone')
    contact.contact_type_id = request.form.get('contact_type_id', type=int) or None
    contact.status_id = request.form.get('status_id', type=int) or None
    db.session.commit()
    return redirect(url_for('contact_detail', contact_id=contact.id))

@app.route('/contact/<int:contact_id>/add_activity', methods=['POST'])
def add_activity(contact_id):
    if request.form['description']:
        new_activity = Activity(description=request.form['description'], contact_id=contact_id, activity_type_id=request.form.get('activity_type_id', type=int))
        db.session.add(new_activity)
        db.session.commit()
    return redirect(url_for('contact_detail', contact_id=contact.id))

# --- Routes for settings page ---
@app.route('/settings')
def settings():
    contact_types = ContactType.query.order_by(ContactType.name).all()
    activity_types = ActivityType.query.order_by(ActivityType.name).all()
    return render_template('settings.html', contact_types=contact_types, activity_types=activity_types)

@app.route('/settings/add_contact_type', methods=['POST'])
def add_contact_type():
    if request.form.get('name'):
        db.session.add(ContactType(name=request.form.get('name')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/add_status', methods=['POST'])
def add_status():
    if request.form.get('name') and request.form.get('contact_type_id'):
        db.session.add(Status(name=request.form.get('name'), contact_type_id=request.form.get('contact_type_id')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/add_activity_type', methods=['POST'])
def add_activity_type():
    if request.form.get('name'):
        db.session.add(ActivityType(name=request.form.get('name')))
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/edit/<item_type>/<int:item_id>', methods=['POST'])
def edit_setting(item_type, item_id):
    if request.form.get('name'):
        model = {'contact_type': ContactType, 'status': Status, 'activity_type': ActivityType}.get(item_type)
        if model:
            item = model.query.get_or_404(item_id)
            item.name = request.form.get('name')
            db.session.commit()
    return redirect(url_for('settings'))

# --- !!! הנה הפונקציה המתוקנת והבטוחה !!! ---
@app.route('/settings/delete/<item_type>/<int:item_id>', methods=['POST'])
def delete_setting(item_type, item_id):
    model_map = {
        'contact_type': ContactType, 'status': Status, 
        'activity_type': ActivityType, 'saved_view': SavedView
    }
    model = model_map.get(item_type)
    
    if model:
        item = model.query.get_or_404(item_id)
        
        # בדיקות בטיחות קריטיות שהוחזרו
        if item_type == 'contact_type' and item.contacts:
            return redirect(url_for('settings')) # נמנע מחיקה אם יש קשרים
        if item_type == 'status' and item.contacts:
            return redirect(url_for('settings')) # נמנע מחיקה אם יש קשרים
        
        db.session.delete(item)
        db.session.commit()

    return redirect(url_for('index') if item_type == 'saved_view' else url_for('settings'))
# ---------------------------------------------

# --- API Endpoints ---
@app.route('/api/save_view', methods=['POST'])
def save_view():
    data = request.get_json()
    if not data or not data.get('name') or data.get('filters') is None:
        return jsonify({'success': False, 'message': 'Missing data'}), 400
    view = SavedView(name=data['name'], filters=data['filters'])
    db.session.add(view)
    db.session.commit()
    return jsonify({'success': True, 'message': 'View saved!', 'view': {'id': view.id, 'name': view.name}})

@app.route('/api/lead', methods=['POST'])
def handle_lead():
    data = request.get_json()
    if not data: return {"error": "Invalid request. Expecting JSON data."}, 400
    email, phone = data.get('email'), data.get('phone')
    if not email and not phone: return {"error": "Either email or phone is required."}, 400
    contact = None
    if email: contact = Contact.query.filter_by(email=email).first()
    if not contact and phone: contact = Contact.query.filter_by(phone=phone).first()
    if not contact:
        name = data.get('name') or email or phone
        contact = Contact(name=name, email=email, phone=phone)
        db.session.add(contact)
        db.session.commit()
    activity_description = f"פנייה חדשה ממקור: {data.get('source', 'לא ידוע')}\n treść wiadomości: {data.get('message', '')}"
    new_activity = Activity(description=activity_description, source=data.get('source', 'לא ידוע'), contact_id=contact.id)
    db.session.add(new_activity)
    db.session.commit()
    return {"success": True, "message": "Lead processed successfully.", "contact_id": contact.id}, 201