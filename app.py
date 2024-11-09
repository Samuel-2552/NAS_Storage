from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import safe_join
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Hardcoded username and password
USERNAME = 'admin'
PASSWORD_HASH = generate_password_hash('password123')  # Use hashed password for security

# Hardcoded second password for accessing the console
CONSOLE_PASSWORD_HASH = generate_password_hash('adminConsolePassword')

# Safe base directory for directory browsing
BASE_DIRECTORY = 'D:/'  # Example safe directory to start from
if not os.path.exists(BASE_DIRECTORY):
    os.makedirs(BASE_DIRECTORY)

# Define a directory for file operations
UPLOAD_FOLDER = 'D:/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Ensure Flask can serve files from the upload directory
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate the username and password
        if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/consoled', methods=['GET', 'POST'])
def console():
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    # If the user is logged in, allow them to enter the console password
    if request.method == 'POST':
        console_password = request.form.get('console_password')
        
        # Check if the entered password matches the hardcoded console password
        if check_password_hash(CONSOLE_PASSWORD_HASH, console_password):
            return render_template('console.html', console_access=True)
        else:
            flash('Invalid console password!', 'danger')
            return render_template('console.html', console_access=False)
    
    return render_template('console.html', console_access=False)

@app.route('/run_command', methods=['POST'])
def run_command():
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    command = request.form.get('command')
    
    # # List of allowed commands for security reasons (can be extended as needed)
    # allowed_commands = ['ls', 'dir', 'echo', 'pwd', 'cat']

    # # Prevent arbitrary commands and execute only allowed commands
    # if command.split()[0] not in allowed_commands:
    #     flash('Invalid or disallowed command!', 'danger')
    #     return redirect(url_for('console'))

    try:
        # Execute the command and capture the output
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
    except Exception as e:
        output = f"Error executing command: {str(e)}"
    
    return render_template('console.html', console_access=True, output=output)

@app.route('/directory_listing')
@app.route('/directory_listing/<path:subdir>')
def directory_listing(subdir=None):
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    # Prevent path traversal by making sure the subdir is within the allowed base directory
    if subdir:
        safe_subdir = safe_join(BASE_DIRECTORY, subdir)
        if not safe_subdir.startswith(BASE_DIRECTORY):
            flash('Invalid directory path.', 'danger')
            return redirect(url_for('directory_listing'))
    else:
        safe_subdir = BASE_DIRECTORY

    # List files and directories in the safe_subdir
    try:
        entries = os.listdir(safe_subdir)
        directories = [entry for entry in entries if os.path.isdir(safe_join(safe_subdir, entry))]
        files = [entry for entry in entries if os.path.isfile(safe_join(safe_subdir, entry))]
    except PermissionError:
        flash('You do not have permission to access this directory.', 'danger')
        return redirect(url_for('directory_listing'))

    return render_template('directory_listing.html', files=files, directories=directories, current_dir=subdir or '')

@app.route('/download/<filename>')
def download_files(filename):
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))

    # Sanitize filename and prevent path traversal attacks
    filename=filename.replace('%2f','/')
    safe_filename = safe_join(BASE_DIRECTORY, filename)
    print(safe_filename)
    if not safe_filename.startswith(BASE_DIRECTORY):
        flash('Invalid file path.', 'danger')
        return redirect(url_for('directory_listing'))
    
    # Send the file to the client as a download
    return send_from_directory(BASE_DIRECTORY, filename, as_attachment=True)

@app.route('/upload', methods=['GET', 'POST'])
def upload_files():
    if 'logged_in' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('directory_listing'))

    return render_template('upload_files.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

