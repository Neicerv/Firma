import os 
import io
from datetime import datetime
import sqlite3
from flask import Flask, render_template, request, redirect, session, send_file, flash, g
from flask_bcrypt import Bcrypt
from flask_session import Session
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import qrcode
import hashlib
from werkzeug.utils import secure_filename

# Configuración de la aplicación Flask
app = Flask(__name__)
app.secret_key = "secret_key"
bcrypt = Bcrypt(app)

# Base de datos
def init_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Función para generar un QR
def generate_qr(data, output_file):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    img.save(output_file)

# Función para generar un hash simple para el PDF
def generate_pdf_hash(pdf_path):
    sha256_hash = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return f"Hash: {sha256_hash.hexdigest()}"

# Función para añadir el QR y texto al PDF
def add_qr_to_pdf(pdf_path, qr_path, output_path, username):
    """
    Agrega un QR y texto en la última página del PDF original.
    """
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)

    # Leer el contenido original
    existing_pdf = PdfReader(pdf_path)
    last_page = existing_pdf.pages[-1]
    width = float(last_page.mediabox.width)
    height = float(last_page.mediabox.height)

    # Texto con el nombre del usuario y la fecha
    signature_text = f"Signed by: {username}\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    can.setFont("Helvetica", 10)
    text_x = width - 150  # Ajustar según el ancho de la página
    text_y = 150  # Ajustar según la posición vertical
    for i, line in enumerate(signature_text.split("\n")):
        can.drawString(text_x, text_y + (10 * (len(signature_text.split("\n")) - i - 1)), line)

    # Dibujar el QR debajo del texto
    qr_x = text_x
    qr_y = text_y - 100  # Ajustar según la posición vertical
    can.drawImage(qr_path, qr_x, qr_y, width=100, height=100)

    can.save()
    packet.seek(0)

    # Fusionar el contenido nuevo con la última página del PDF original
    new_pdf = PdfReader(packet)
    writer = PdfWriter()

    for i, page in enumerate(existing_pdf.pages):
        if i == len(existing_pdf.pages) - 1:
            # Combinar la última página con el QR y texto
            page.merge_page(new_pdf.pages[0])
        writer.add_page(page)

    # Guardar el archivo resultante
    with open(output_path, "wb") as outputStream:
        writer.write(outputStream)

# Ruta para la página principal
@app.route('/')
def index():
    return redirect('/login')

# Ruta para el login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect("users.db", check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user'] = username
            return redirect('/dashboard')
        return "Credenciales inválidas. Inténtalo nuevamente."
    return render_template('login.html')

# Ruta para registrarse
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        try:
            conn = sqlite3.connect("users.db", check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "El usuario ya existe. Inténtalo con otro nombre."
    return render_template('register.html')

# Ruta para el dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user=session['user'])

# Ruta para firmar PDF
@app.route('/sign-pdf', methods=['GET', 'POST'])
def sign_pdf():
    if 'user' not in session:
        return redirect('/login')

    if request.method == 'POST':
        uploaded_file = request.files['pdf']
        if uploaded_file.filename != '' and allowed_file(uploaded_file.filename):
            # Guardar el PDF subido
            upload_folder = 'uploads'
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            original_path = os.path.join(upload_folder, secure_filename(uploaded_file.filename))
            uploaded_file.save(original_path)

            # Proceso de firma
            pdf_hash = generate_pdf_hash(original_path)
            qr_path = os.path.join(upload_folder, "qr_signature.png")
            signed_pdf_path = os.path.join(upload_folder, f"signed_{uploaded_file.filename}")

            generate_qr(pdf_hash, qr_path)
            add_qr_to_pdf(original_path, qr_path, signed_pdf_path, session['user'])

            return send_file(signed_pdf_path, as_attachment=True)
        else:
            flash("Solo se permiten archivos PDF.")
    return render_template('sign_pdf.html')

# Ruta para el logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
