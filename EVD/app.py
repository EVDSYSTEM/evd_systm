from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
import sqlite3
import bcrypt
import random
import os
import subprocess
import zipfile
from datetime import datetime
from flask_mail import Mail, Message


app = Flask(__name__)
app.secret_key = 'key'

# Set the path to the uploads directory
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('local_users.db')
    conn.row_factory = sqlite3.Row
    return conn

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'evd6764@gmail.com'  
app.config['MAIL_PASSWORD'] = 'ulso yzjj hbru ubtv'   
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)


# Create the users table if it doesn't exist
def create_table(conn):
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Exception as e:  # Catching general exceptions
        print(e)

# Home page (Signup/Login forms)
@app.route('/')
def index():
    logged_in = session.get('logged_in', False)  # Get logged_in status from session
    return render_template('index.html', logged_in=logged_in)

# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                       (username, email, hashed_password))
        conn.commit()
        flash('Signup successful! You can now login.', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists!', 'danger')
    finally:
        conn.close()

    return redirect(url_for('login'))

# Show login page
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# Login route
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password'].encode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password, user['password']):
        session['loggedin'] = True
        session['username'] = user['username']
        session['logged_in'] = True  # Set logged_in in session
        flash(f'Welcome back, {user["username"]}!', 'success')
        return redirect(url_for('index'))  # Redirect to the home page
    else:
        flash('Invalid login credentials.', 'danger')
        return redirect(url_for('login_page'))



# Dashboard route (protected)
@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        return render_template('dashboard.html', username=session['username'])  # Render dashboard template
    return redirect(url_for('index'))

# Object detection function
def run_detection():
    try:
        random_number = random.randint(1, 1000)
        old_folder_path = "static/output/exp"
        new_folder_path = f"static/output/exp_{random_number}"
        os.rename(old_folder_path, new_folder_path)
    except Exception as e:
        print(f"Error creating folder: {e}")

    command = "python yolov5/detect.py --weights yolov5/runs/train/exp20/weights/best.pt --source static/uploads/img.jpg --conf-thres 0.5 --save-txt --project static/output"
    subprocess.Popen(command, shell=True)

# Upload and detection route
@app.route('/detect', methods=['POST'])
def detect():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            file.save("static/uploads/img.jpg")  # Save the uploaded file
            run_detection()  # Call the object detection function

            # In a real scenario, you would process the detection results and pass them to the template
            detection_results = "Results of object detection"  # Placeholder for detection results

            return render_template('dashboard.html', username=session['username'], results=detection_results)

    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# About page route
@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Create the message
        msg = Message('New Contact Form Submission',
                      sender=email,
                      recipients=['evd6764@gmail.com'])  # Change to the recipient email
        msg.body = f"""
        Name: {name}
        Email: {email}
        Message: {message}
        """

        try:
            mail.send(msg)
            flash('Your message has been sent successfully!', 'success')
        except Exception as e:
            print(f"Failed to send email: {e}")
            flash('An error occurred. Please try again later.', 'danger')

        return redirect(url_for('contact'))

    return render_template('contact.html')




@app.route('/static/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/zip-folder', methods=['POST'])
def zip_folder():
    data = request.get_json()
    folder_path = data['folderPath']

    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")
    zip_filename = f'saved/Emergency_Vehicle_Detection_{formatted_datetime}.zip'

    zipf = zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED)
    for root, _, files in os.walk(folder_path):
        for file in files:
            zipf.write(os.path.join(root, file))
    zipf.close()

    return send_file(zip_filename, as_attachment=True)

if __name__ == '__main__':
    database = "local_users.db"
    conn = get_db_connection()

    if conn is not None:
        create_table(conn)  # Make sure to create the table
        conn.close()  # Close the connection

    app.run(debug=True)  # Start the Flask app
