# Dockerfile

# 1. השתמש באימג' רשמי של פייתון כבסיס
FROM python:3.9-slim

# 2. הגדר את תיקיית העבודה בתוך הקונטיינר
WORKDIR /app

# 3. העתק את קובץ הדרישות והתקן אותן
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# 4. העתק את כל קבצי הפרויקט לתוך הקונטיינר
COPY . .

# 5. הענק הרשאות הרצה לקובץ ה-entrypoint
RUN chmod +x /app/entrypoint.sh

# 6. הגדר את קובץ ה-entrypoint כפקודת ההפעלה
CMD ["/app/entrypoint.sh"]