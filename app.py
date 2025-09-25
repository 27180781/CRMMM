from sqlalchemy import or_ # הוסף שורה זו בראש הקובץ, יחד עם שאר ה-import-ים
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
# 1. הגדרת האפליקציה ומסד הנתונים
app = Flask(__name__)
# קריאת כתובת מסד הנתונים ממשתנה סביבה (לסביבת פרודקשן)
# אם המשתנה לא קיים, חוזרים להשתמש ב-SQLite המקומי (לסביבת פיתוח)
database_url = os.environ.get('DATABASE_URL') or 'sqlite:///crm.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- הוסף את הקוד הבא ---
# הגדרת "מוסכמת שמות" כדי למנוע שגיאות ב-SQLite
metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)
db = SQLAlchemy(app, metadata=metadata)# -------------------------
migrate = Migrate(app, db) # אתחול של Flask-Migrate

# 2. הגדרת מודלים (טבלאות מסד הנתונים)
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    # שדות חדשים המקשרים לטבלאות ההגדרות
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'), nullable=True)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=True)

    # קשרים שיאפשרו לנו לגשת לאובייקטים עצמם בקלות
    contact_type = db.relationship('ContactType', backref='contacts')
    status = db.relationship('Status', backref='contacts')

    activities = db.relationship('Activity', backref='contact', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Contact {self.name}>'

# --- הוסף מודלים חדשים ---
class ContactType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    statuses = db.relationship('Status', backref='contact_type', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return self.name

class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    contact_type_id = db.Column(db.Integer, db.ForeignKey('contact_type.id'), nullable=False)

    def __repr__(self):
        return self.name
# --------------------------

    def __repr__(self):
        return f'<Contact {self.name}>'

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(100)) # לדוגמה: "טופס צור קשר באתר", "קמפיין פייסבוק"
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    # קישור לאיש הקשר הספציפי באמצעות מפתח זר
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)

    def __repr__(self):
        return f'<Activity {self.id} for contact {self.contact_id}>'
    
class SavedView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # שדה JSON גמיש לשמירת כל הגדרות הסינון והמיון
    filters = db.Column(db.JSON, nullable=False) 

    def __repr__(self):
        return self.name

# 3. הגדרת נתיבים (Routes) ופעולות
@app.route('/')
def index():
    """הדף הראשי - מציג את כל אנשי הקשר, עם יכולות סינון"""
    query = Contact.query

    # --- לוגיקת סינון ---
    contact_type_filter = request.args.get('contact_type_id', type=int)
    if contact_type_filter:
        query = query.filter(Contact.contact_type_id == contact_type_filter)

    status_filter = request.args.getlist('status_id', type=int) # קבלת רשימת סטטוסים
    if status_filter:
        query = query.filter(Contact.status_id.in_(status_filter))

    # --- לוגיקת מיון ---
    sort_by = request.args.get('sort_by', 'created_at_desc') # ברירת מחדל: תאריך יצירה יורד
    if sort_by == 'created_at_asc':
        query = query.order_by(Contact.created_at.asc())
    elif sort_by == 'updated_at_desc':
        query = query.order_by(Contact.updated_at.desc())
    elif sort_by == 'updated_at_asc':
        query = query.order_by(Contact.updated_at.asc())
    else: # created_at_desc
        query = query.order_by(Contact.created_at.desc())

    contacts = query.all()
    
    # שליפת כל המידע הנדרש עבור טופס הסינון
    contact_types = ContactType.query.all()
    # שליפת כל הסטטוסים כדי שנוכל לסנן אותם באופן דינמי ב-JavaScript
    all_statuses = Status.query.all()
    
    return render_template('index.html', 
                           contacts=contacts, 
                           contact_types=contact_types,
                           all_statuses=all_statuses,
                           # העברת ערכי הסינון הנוכחיים חזרה לתבנית
                           active_type_filter=contact_type_filter,
                           active_status_filter=status_filter,
                           active_sort=sort_by)
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

@app.route('/contact/<int:contact_id>')
def contact_detail(contact_id):
    """מציג כרטיס לקוח עם כל הפרטים והפעילויות"""
    contact = Contact.query.get_or_404(contact_id)
    # מציג את הפעילויות מהחדשה לישנה
    activities = Activity.query.filter_by(contact_id=contact.id).order_by(Activity.timestamp.desc()).all()
    return render_template('contact_detail.html', contact=contact, activities=activities)

@app.route('/contact/<int:contact_id>/add_activity', methods=['POST'])
def add_activity(contact_id):
    """מוסיף רשומת פעילות חדשה לאיש קשר"""
    contact = Contact.query.get_or_404(contact_id)
    description = request.form['description']
    if description:
        new_activity = Activity(description=description, contact_id=contact.id)
        db.session.add(new_activity)
        db.session.commit()
    return redirect(url_for('contact_detail', contact_id=contact.id))
# --- הוסף את הקוד הזה ---

@app.route('/settings')
def settings():
    """מציג את עמוד ההגדרות הראשי"""
    contact_types = ContactType.query.order_by(ContactType.name).all()
    return render_template('settings.html', contact_types=contact_types)

@app.route('/settings/add_contact_type', methods=['POST'])
def add_contact_type():
    """מוסיף סוג רישום חדש"""
    name = request.form.get('name')
    if name:
        new_type = ContactType(name=name)
        db.session.add(new_type)
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/settings/add_status', methods=['POST'])
def add_status():
    """מוסיף סטטוס חדש לסוג רישום קיים"""
    name = request.form.get('name')
    contact_type_id = request.form.get('contact_type_id')
    if name and contact_type_id:
        new_status = Status(name=name, contact_type_id=contact_type_id)
        db.session.add(new_status)
        db.session.commit()
    return redirect(url_for('settings'))

# --- סוף הקוד להוספה ---
@app.route('/api/lead', methods=['POST'])
def handle_lead():
    """
    נקודת קצה לקליטת לידים חדשים.
    מקבלת JSON עם פרטי הליד, מוצאת איש קשר קיים או יוצרת חדש,
    ומוסיפה לו פעילות חדשה עם פרטי הפנייה.
    """
    data = request.get_json()
    if not data:
        return {"error": "Invalid request. Expecting JSON data."}, 400

    # איסוף הנתונים מהבקשה
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    message = data.get('message', '') # הודעה היא אופציונלית
    source = data.get('source', 'לא ידוע') # מקור הוא אופציונלי

    # תנאי מינימום: חייב להיות לפחות טלפון או אימייל
    if not email and not phone:
        return {"error": "Either email or phone is required to create a lead."}, 400

    contact = None
    # לוגיקת החיפוש: מצא איש קשר אם יש התאמה במייל או בטלפון (בהנחה שהם לא ריקים)
    if email:
        contact = Contact.query.filter_by(email=email).first()
    if not contact and phone:
        contact = Contact.query.filter_by(phone=phone).first()

    # אם לא נמצא איש קשר, ניצור אחד חדש
    if not contact:
        # אם אין שם, נשתמש במייל או בטלפון כשם זמני
        if not name:
            name = email or phone
        
        contact = Contact(name=name, email=email, phone=phone)
        db.session.add(contact)
        # חשוב לבצע commit כאן כדי שה-ID של איש הקשר החדש יהיה זמין
        db.session.commit() 
    
    # יצירת הפעילות (ההתקשרות) ותיעוד המקור וההודעה
    activity_description = f"פנייה חדשה ממקור: {source}\n treść wiadomości: {message}"
    
    new_activity = Activity(
        description=activity_description,
        source=source,
        contact_id=contact.id
    )
    db.session.add(new_activity)
    db.session.commit()

    return {"success": True, "message": "Lead processed successfully.", "contact_id": contact.id}, 201
