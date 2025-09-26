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

# 5. הפקודה שתרוץ כאשר הקונטיינר יופעל (בשורה אחת)
CMD ["sh", "-c", "python -c 'import os, time, psycopg2; db_url = os.environ.get(\"DATABASE_URL\"); retries = 10; while retries > 0:
 try: psycopg2.connect(db_url); print(\"DB Ready!\"); break;
 except psycopg2.OperationalError: retries -= 1; print(\"Waiting for DB...\"); time.sleep(3);' && flask db upgrade && gunicorn --bind 0.0.0.0:80 app:app"]