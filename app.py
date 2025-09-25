# app.py

from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# 1. הגדרת האפליקציה ומסד הנתונים
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db' # הגדרת מסד הנתונים - קובץ בשם crm.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 2. הגדרת מודל - איך ייראה "איש קשר" במסד הנתונים
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True) # מזהה ייחודי
    name = db.Column(db.String(100), nullable=False) # שם מלא
    email = db.Column(db.String(100), unique=True) # אימייל (ייחודי)
    phone = db.Column(db.String(20)) # טלפון
    status = db.Column(db.String(50), default='ליד חדש') # סטטוס (למשל, ליד חדש, נוצר קשר, לקוח)

    def __repr__(self):
        return f'<Contact {self.name}>'

# 3. יצירת מסד הנתונים (אם הוא לא קיים)
# יש להריץ פעם אחת בלבד מהטרמינל לפני הפעלת האפליקציה
@app.cli.command('init-db')
def init_db_command():
    """יוצר את טבלאות מסד הנתונים."""
    db.create_all()
    print('Initialized the database.')

# 4. הגדרת נתיבים (Routes) באפליקציה
@app.route('/')
def index():
    """הדף הראשי - מציג את כל אנשי הקשר"""
    contacts = Contact.query.all() # שליפת כל אנשי הקשר ממסד הנתונים
    return render_template('index.html', contacts=contacts)

@app.route('/add', methods=['GET', 'POST'])
def add_contact():
    """דף להוספת איש קשר חדש"""
    if request.method == 'POST':
        # אם הטופס נשלח (בשיטת POST)
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        
        # יצירת אובייקט איש קשר חדש
        new_contact = Contact(name=name, email=email, phone=phone)
        
        # שמירה במסד הנתונים
        db.session.add(new_contact)
        db.session.commit()
        
        return redirect(url_for('index')) # חזרה לדף הראשי
    
    # אם נכנסים לדף בפעם הראשונה (בשיטת GET)
    return render_template('add_contact.html')

if __name__ == '__main__':
    app.run(debug=True)