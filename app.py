import os
import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# 1. הגדרת האפליקציה ומסד הנתונים
app = Flask(__name__)
# קריאת כתובת מסד הנתונים ממשתנה סביבה (לסביבת פרודקשן)
# אם המשתנה לא קיים, חוזרים להשתמש ב-SQLite המקומי (לסביבת פיתוח)
database_url = os.environ.get('DATABASE_URL') or 'sqlite:///crm.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db) # אתחול של Flask-Migrate

# 2. הגדרת מודלים (טבלאות מסד הנתונים)
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    status = db.Column(db.String(50), default='ליד חדש')
    # יצירת קשר לפעילויות - לכל איש קשר יש רשימה של פעילויות
    activities = db.relationship('Activity', backref='contact', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Contact {self.name}>'

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    # קישור לאיש הקשר הספציפי באמצעות מפתח זר
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)

    def __repr__(self):
        return f'<Activity {self.id} for contact {self.contact_id}>'

# 3. הגדרת נתיבים (Routes) ופעולות
@app.route('/')
def index():
    """הדף הראשי - מציג את כל אנשי הקשר"""
    contacts = Contact.query.order_by(Contact.name).all()
    return render_template('index.html', contacts=contacts)

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
    contact = Contact.query.get_or_4404(contact_id)
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