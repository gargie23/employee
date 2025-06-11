import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-me'
app.config['SESSION_TYPE'] = 'filesystem'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['LETTER_FOLDER'] = 'static/letters'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png'}

# Create necessary folders
for folder in [app.config['UPLOAD_FOLDER'], app.config['LETTER_FOLDER']]:
    if not os.path.exists(folder):
        os.makedirs(folder)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100))  # New field for DO profile
    phone = db.Column(db.String(20))       # New field for DO profile
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # user, do, head
    id_proof = db.Column(db.String(100))
    aadhar_proof = db.Column(db.String(100))
    fir_receipt = db.Column(db.String(100))
    approved = db.Column(db.Boolean, default=False)
    profile_complete = db.Column(db.Boolean, default=False)  # New field for DOs

    def can_access_letters(self):
        if self.role == 'head':
            return True
        if self.role == 'do' and self.profile_complete:
            return True
        return False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_submitted_docs(self):
        return (self.id_proof and self.aadhar_proof) or self.fir_receipt

class Letter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='draft')  # draft, submitted, officer_approved, officer_rejected, head_approved, head_rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    filename = db.Column(db.String(100))
    officer_remark = db.Column(db.Text)
    head_remark = db.Column(db.Text)
    officer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    head_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship('User', foreign_keys=[user_id], backref='letters')
    officer = db.relationship('User', foreign_keys=[officer_id])
    head = db.relationship('User', foreign_keys=[head_id])

    def can_view(self, user):
        if user.role == 'head':
            return True
        if user.role == 'officer' and self.status in ['submitted', 'officer_approved', 'officer_rejected']:
            return True
        if user.id == self.user_id:
            return True
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

def redirect_based_on_role(user):
    if user.role == 'head':
        return redirect(url_for('head_dashboard'))
    elif user.role == 'officer':
        return redirect(url_for('officer_dashboard'))
    elif not user.has_submitted_docs():
        return redirect(url_for('profile'))
    elif not user.approved:
        return redirect(url_for('pending_approval'))
    else:
        return redirect(url_for('home'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect_based_on_role(current_user)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect_based_on_role(current_user)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect_based_on_role(user)
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect_based_on_role(current_user)
    
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        designation = request.form['designation']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            full_name=full_name,
            designation=designation,
            role='user'
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('profile'))
    
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        id_proof = request.files.get('id_proof')
        aadhar_proof = request.files.get('aadhar_proof')
        fir_receipt = request.files.get('fir_receipt')
        
        if id_proof:
            current_user.id_proof = save_uploaded_file(id_proof)
        if aadhar_proof:
            current_user.aadhar_proof = save_uploaded_file(aadhar_proof)
        if fir_receipt:
            current_user.fir_receipt = save_uploaded_file(fir_receipt)
        
        db.session.commit()
        flash('Documents uploaded successfully!')
        return redirect(url_for('pending_approval'))
    
    return render_template('profile.html')

@app.route('/pending_approval')
@login_required
def pending_approval():
    if current_user.approved:
        return redirect_based_on_role(current_user)
    return render_template('pending_approval.html')

@app.route('/home')
@login_required
def home():
    if not current_user.approved:
        return redirect(url_for('pending_approval'))
    if not current_user.has_submitted_docs():
        return redirect(url_for('profile'))
    return render_template('home.html')

@app.route('/generate_letter/<letter_type>', methods=['GET', 'POST'])
@login_required
def generate_letter(letter_type):
    if not current_user.approved:
        return redirect(url_for('pending_approval'))
    
    # Define our sample letters
    sample_letters = {
        'permission': {
            'title': 'Permission Letter for Event Participation',
            'content': f"""To,
The Authority Concerned
[Organization Name]
[Address]

Subject: Request for Permission to Participate in [Event Name]

Dear Sir/Madam,

I, {current_user.full_name} ({current_user.designation}), would like to request permission to participate in [Event Name] scheduled on [Date]. 

I assure you that I will follow all the rules and regulations during the event. Kindly grant me permission to participate.

Thanking you,
Yours sincerely,
{current_user.full_name}
{current_user.designation}"""
        },
        'noc': {
            'title': 'No Objection Certificate Request',
            'content': f"""To,
The Authority Concerned
[Organization Name]
[Address]

Subject: Request for No Objection Certificate

Dear Sir/Madam,

I, {current_user.full_name} ({current_user.designation}), am writing to request a No Objection Certificate for [Purpose]. 

I would be grateful if you could issue the NOC at the earliest convenience.

Thanking you,
Yours sincerely,
{current_user.full_name}
{current_user.designation}"""
        },
        'leave': {
            'title': 'Leave Application',
            'content': f"""To,
The Authority Concerned
[Organization Name]
[Address]

Subject: Application for Leave

Dear Sir/Madam,

I, {current_user.full_name} ({current_user.designation}), would like to apply for leave from [Start Date] to [End Date] due to [Reason]. 

I request you to kindly grant me leave for the mentioned period.

Thanking you,
Yours sincerely,
{current_user.full_name}
{current_user.designation}"""
        }
    }
    
    if letter_type not in sample_letters:
        flash('Invalid letter type')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Create and submit the letter
        letter = Letter(
            title=sample_letters[letter_type]['title'],
            content=sample_letters[letter_type]['content'],
            user_id=current_user.id,
            status='submitted'
        )
        db.session.add(letter)
        db.session.commit()
        flash('Letter submitted for approval!')
        return redirect(url_for('home'))
    
    # For GET request, show the letter preview
    return render_template(
        'generate_letter.html', 
        letter=sample_letters[letter_type],
        letter_type=letter_type,
        now=datetime.now()
    )

@app.route('/view_letter/<int:letter_id>')
@login_required
def view_letter(letter_id):
    letter = Letter.query.get_or_404(letter_id)
    if not letter.can_view(current_user):
        flash('You are not authorized to view this letter')
        return redirect_based_on_role(current_user)
    
    # Store referrer URL - using Flask's built-in session
    referrer = request.referrer
    if referrer and ('head/dashboard' in referrer or 'officer/dashboard' in referrer):
        session['previous_url'] = referrer  # Using Flask's native session
    
    return render_template('view_letter.html', letter=letter)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/head/dashboard')
@login_required
def head_dashboard():
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    pending_letters = Letter.query.filter_by(status='officer_approved').order_by(Letter.created_at.desc()).all()
    reviewed_letters = Letter.query.filter(
        Letter.status.in_(['head_approved', 'head_rejected']),
        Letter.head_id == current_user.id
    ).order_by(Letter.updated_at.desc()).all()
    pending_users = User.query.filter(
        User.role == 'user',
        User.approved == False,
        db.or_(
            User.id_proof.isnot(None),
            User.aadhar_proof.isnot(None),
            User.fir_receipt.isnot(None)
        )
    ).all()
    officers = User.query.filter_by(role='officer').all()
    
    return render_template('head_dashboard.html',
                         pending_letters=pending_letters,
                         reviewed_letters=reviewed_letters,
                         pending_users=pending_users,
                         officers=officers)

@app.route('/head/approve_user/<int:user_id>')
@login_required
def head_approve_user(user_id):
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    user = User.query.get_or_404(user_id)
    if user.has_submitted_docs():
        user.approved = True
        db.session.commit()
        flash(f'User {user.username} approved successfully!')
    else:
        flash('User has not submitted all documents', 'error')
    return redirect(url_for('head_dashboard'))

@app.route('/head/reject_user/<int:user_id>')
@login_required
def head_reject_user(user_id):
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    user = User.query.get_or_404(user_id)
    user.id_proof = None
    user.aadhar_proof = None
    user.fir_receipt = None
    user.approved = False
    db.session.commit()
    flash(f'User {user.username} documents rejected. Please resubmit.')
    return redirect(url_for('head_dashboard'))

@app.route('/head/create_do', methods=['GET', 'POST'])  
@login_required
def head_create_do():
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        designation = request.form['designation']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('head_create_do'))
        
        new_do = User(
            username=username,
            full_name=full_name,
            designation=designation,
            role='do',  
            approved=True,
            profile_complete=False  # DO needs to complete profile
        )
        new_do.set_password(password)
        db.session.add(new_do)
        db.session.commit()
        flash('DO account created successfully!')
        return redirect(url_for('head_dashboard'))
    
    return render_template('create_do.html')  

@app.route('/do/profile', methods=['GET', 'POST'])
@login_required
def do_profile():
    if current_user.role != 'do' or current_user.profile_complete:
        return redirect_based_on_role(current_user)
    
    if request.method == 'POST':
        department = request.form['department']
        phone = request.form['phone']
        id_proof = request.files['id_proof']
        aadhar_proof = request.files['aadhar_proof']
        
        # Save files and update user
        current_user.department = department
        current_user.phone = phone
        current_user.id_proof = save_uploaded_file(id_proof)
        current_user.aadhar_proof = save_uploaded_file(aadhar_proof)
        current_user.profile_complete = True
        
        db.session.commit()
        flash('Profile completed successfully!')
        return redirect(url_for('do_dashboard'))
    
    return render_template('do_profile.html')

@app.route('/head/approve_letter/<int:letter_id>', methods=['GET', 'POST'])
@login_required
def head_approve_letter(letter_id):
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    letter = Letter.query.get_or_404(letter_id)
    if letter.status != 'officer_approved':
        flash('Letter is not in correct state for approval', 'error')
        return redirect(url_for('head_dashboard'))
    
    if request.method == 'POST':
        letter.status = 'head_approved'
        letter.head_id = current_user.id
        letter.head_remark = request.form.get('remark', '')
        db.session.commit()
        flash('Letter approved successfully!')
        return redirect(url_for('head_dashboard'))
    
    return render_template('approve_letter.html', 
                         letter=letter, 
                         action='approve',
                         role='head')

@app.route('/head/reject_letter/<int:letter_id>', methods=['GET', 'POST'])
@login_required
def head_reject_letter(letter_id):
    if current_user.role != 'head':
        return redirect_based_on_role(current_user)
    
    letter = Letter.query.get_or_404(letter_id)
    if letter.status != 'officer_approved':
        flash('Letter is not in correct state for rejection', 'error')
        return redirect(url_for('head_dashboard'))
    
    if request.method == 'POST':
        remark = request.form.get('remark', '')
        if not remark:
            flash('Please provide a rejection remark', 'error')
            return redirect(url_for('head_reject_letter', letter_id=letter_id))
        
        letter.status = 'head_rejected'
        letter.head_id = current_user.id
        letter.head_remark = remark
        db.session.commit()
        flash('Letter rejected successfully!')
        return redirect(url_for('head_dashboard'))
    
    return render_template('approve_letter.html', 
                         letter=letter, 
                         action='reject',
                         role='head')

@app.route('/officer/dashboard')
@login_required
def officer_dashboard():
    if current_user.role != 'officer':
        return redirect_based_on_role(current_user)
    
    pending_letters = Letter.query.filter_by(status='submitted').order_by(Letter.created_at.desc()).all()
    reviewed_letters = Letter.query.filter(
        Letter.status.in_(['officer_approved', 'officer_rejected']),
        Letter.officer_id == current_user.id
    ).order_by(Letter.updated_at.desc()).all()
    
    return render_template('officer_dashboard.html',
                         pending_letters=pending_letters,
                         reviewed_letters=reviewed_letters)

@app.route('/officer/approve_letter/<int:letter_id>', methods=['GET', 'POST'])
@login_required
def officer_approve_letter(letter_id):
    if current_user.role != 'officer':
        return redirect_based_on_role(current_user)
    
    letter = Letter.query.get_or_404(letter_id)
    if letter.status != 'submitted':
        flash('Letter is not in correct state for approval', 'error')
        return redirect(url_for('officer_dashboard'))
    
    if request.method == 'POST':
        remark = request.form.get('remark', '')
        letter.status = 'officer_approved'
        letter.officer_id = current_user.id
        letter.officer_remark = remark
        db.session.commit()
        flash('Letter approved and sent to head for final review!')
        return redirect(url_for('officer_dashboard'))
    
    return render_template('approve_reject_letter.html', 
                         letter=letter, 
                         action='approve',
                         role='officer')

@app.route('/officer/reject_letter/<int:letter_id>', methods=['GET', 'POST'])
@login_required
def officer_reject_letter(letter_id):
    if current_user.role != 'officer':
        return redirect_based_on_role(current_user)
    
    letter = Letter.query.get_or_404(letter_id)
    if letter.status != 'submitted':
        flash('Letter is not in correct state for rejection', 'error')
        return redirect(url_for('officer_dashboard'))
    
    if request.method == 'POST':
        remark = request.form.get('remark', '')
        if not remark:
            flash('Rejection remark is required', 'error')
            return redirect(url_for('officer_reject_letter', letter_id=letter_id))
        
        letter.status = 'officer_rejected'
        letter.officer_id = current_user.id
        letter.officer_remark = remark
        db.session.commit()
        flash('Letter rejected successfully!')
        return redirect(url_for('officer_dashboard'))
    
    return render_template('approve_reject_letter.html', 
                         letter=letter, 
                         action='reject',
                         role='officer')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create head if not exists
        if not User.query.filter_by(role='head').first():
            head = User(
                username='head',
                full_name='Senior DO',
                designation='Head Department Officer',
                role='head',
                approved=True,
                profile_complete=True
            )
            head.set_password('head123')
            db.session.add(head)
            db.session.commit()
        
        # Create sample DO if none exists
        if not User.query.filter_by(role='do').first():
            do = User(
                username='do',
                full_name='Department Officer',
                designation='DO',
                role='do',
                approved=True,
                profile_complete=False
            )
            do.set_password('do123')
            db.session.add(do)
            db.session.commit()
    app.run(debug=True)