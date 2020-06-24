from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo, DataRequired
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime
from matplotlib import pyplot as plt
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/inali/PycharmProjects/my_first_flask/database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ROLES = [('Doctor', 'Medic'), ('Patient', 'Pacient'), ('Admin', 'Admin')]
CURR_USR = current_user


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(25))
    last_name = db.Column(db.String(25))
    CNP = db.Column(db.String(15))
    email = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(15))
    is_active = db.Column(db.Integer)
    is_deleted = db.Column(db.Integer)


class AssignedPatients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer)
    patient_id = db.Column(db.Integer)
    pending = db.Column(db.Boolean)


class Device(db.Model):  # tabel deja populat de toate device-urile existente
    id = db.Column(db.Integer, primary_key=True)
    device_key = db.Column(db.Integer)
    user_id = db.Column(db.Integer)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    relation_id = db.Column(db.Integer)
    datetime = db.Column(db.DateTime)
    text = db.Column(db.String)


class Stat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer)
    datetime = db.Column(db.DateTime)
    data = db.Column(db.String)


class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer)
    datetime = db.Column(db.DateTime)
    first_name = db.Column(db.String(25))
    last_name = db.Column(db.String(25))
    email = db.Column(db.String(30))
    message = db.Column(db.String)
    admin_id = db.Column(db.Integer)
    admin_note = db.Column(db.String)
    closed = db.Column(db.Integer)
    closed_datetime = db.Column(db.DateTime)


class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[InputRequired(), Email(message='Email invalid'), Length(max=30)])
    password = PasswordField(label='parola', validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField(label='remember me')


class ChangeInfoForm(FlaskForm):
    first_name = StringField(label='Prenume', validators=[InputRequired(), Length(min=3, max=25)])
    last_name = StringField(label='Nume', validators=[InputRequired(), Length(min=3, max=25)])
    email = StringField(label='Email', validators=[InputRequired(), Email(message='Email invalid'), Length(max=30)])
    password = PasswordField(label='Parola', validators=[InputRequired(), Length(min=6, max=80)])
    confirm_password = PasswordField(label='Confirmati parola', validators=[InputRequired(), Length(min=6, max=80),
                                                                            EqualTo(fieldname='password',
                                                                                    message='Parolele nu sunt identice')])
    delete = BooleanField('Doresc să șterg acest cont')


class ModifyUserInfoForm(FlaskForm):
    first_name = StringField(label='Prenume', validators=[InputRequired(), Length(min=3, max=25)])
    last_name = StringField(label='Nume', validators=[InputRequired(), Length(min=3, max=25)])
    cnp = StringField(label='CNP', validators=[InputRequired(), Length(min=4, max=25)])
    email = StringField(label='Email', validators=[InputRequired(), Email(message='Email invalid'), Length(max=30)])
    role = SelectField(label='Rol', choices=ROLES)


class NoteForm(FlaskForm):
    note_text = StringField(label='Adăugați o notiță', validators=[InputRequired(), Length(min=4, max=1000)], render_kw={'class': 'form-control'})
    mytextarea = TextAreaField(u"Content", render_kw={'class': 'form-control', 'rows': 5})


class AssignPatientForm(FlaskForm):
    CNP = StringField('CNP pacient', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('email', validators=[InputRequired(), Email(message='email invalid'), Length(max=30)])


class RegisterForm(FlaskForm):
    first_name = StringField(label='Prenume', validators=[InputRequired(), Length(min=3, max=25)])
    last_name = StringField(label='Nume', validators=[InputRequired(), Length(min=3, max=25)])
    cnp = StringField(label='CNP', validators=[InputRequired(), Length(min=4, max=25)])
    email = StringField(label='Email', validators=[InputRequired(), Email(message='Email invalid'), Length(max=30)])
    password = PasswordField(label='Parola', validators=[InputRequired(), Length(min=6, max=80)])
    confirm_password = PasswordField(label='Confirmati parola', validators=[InputRequired(), Length(min=6, max=80),
                                                                            EqualTo(fieldname='password',
                                                                                    message='Parolele nu sunt identice')])
    role = SelectField(label='Rol', choices=ROLES)
    remember = BooleanField('remember me')
    gdpr = BooleanField('Sunt de acord cu prelucrarea', validators=[DataRequired(message='Fără a accepta prelucrarea datelor cu caracter personal, nu vă putem crea contul')])


class DeviceForm(FlaskForm):
    device_key = StringField('Cod', validators = [InputRequired(), Length(4)])


class ContactForm(FlaskForm):
    first_name = StringField(label='Prenume', validators=[InputRequired(), Length(min=3, max=25)])
    last_name = StringField(label='Nume', validators=[InputRequired(), Length(min=3, max=25)])
    email = StringField(label='Email', validators=[InputRequired(), Email(message='Email invalid'), Length(max=30)])
    message = StringField(label='Mesaj', validators=[InputRequired(), Length(min=5)])


@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        if current_user.role:
            curr_usr_role = current_user.role
            return render_template('index.html', logged_in=1, curr_usr_role=curr_usr_role)
    except AttributeError:
        return render_template('index.html', logged_in=0)


@app.route('/get_data', methods=['GET', 'POST'])
def get_data():
    data = request.json
    app.logger.info(type(data))
    #app.logger.info(data['uploaded_data'])
    app.logger.info(data['datetime'])
    app.logger.info(data['device_key'])
    app.logger.info(type(datetime.datetime.strptime(data['datetime'], '%Y-%m-%d %H:%M:%S')))
    user_id = Device.query.filter_by(device_key=data['device_key']).first().user_id
    app.logger.info(user_id)
    new_stat = Stat(patient_id=user_id, datetime=datetime.datetime.strptime(data['datetime'], '%Y-%m-%d %H:%M:%S'), data=data['uploaded_data'])
    db.session.add(new_stat)
    db.session.commit()
    flash(data)
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data) and not user.is_deleted:
                login_user(user, remember=form.remember.data)
                flash('Welcome!')
                app.logger.info(current_user)
                if current_user.role == 'Admin':
                    return redirect(url_for('dashboard_admin'))
                if current_user.is_active:
                    return redirect(url_for('dashboard'))
                else:
                    flash('Contul dumneavoastră este dezactivat, contactați un administrator pentru a îl reactiva!')
                    return redirect(url_for('contact'))

        flash('Email sau parola invalida')

    return render_template('login.html', form = form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        new_user = User(first_name=form.first_name.data, last_name=form.last_name.data, CNP=form.cnp.data,
                        email=form.email.data, password=hashed_password, role=form.role.data,
                        is_active=1, is_deleted=0)
        db.session.add(new_user)
        db.session.commit()

        flash('A fost creat un nou utilizator! Intrați în cont pentru a-l putea utiliza')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/change_info', methods=['GET', 'POST'])
@login_required
def change_info():
    form = ChangeInfoForm(first_name=current_user.first_name, last_name=current_user.last_name,
                          email=current_user.email)
    if form.validate_on_submit():
        if form.delete.data == 1:
            app.logger.info('2')
            device = Device.query.filter_by(user_id=current_user.id).first()
            if device:
                device.user_id = -1
                db.session.commit()
            relations = AssignedPatients.query.filter_by(doctor_id=current_user.id)
            for relation in relations:
                db.session.delete(relation)
            db.session.commit()
            relations = AssignedPatients.query.filter_by(patient_id=current_user.id)
            for relation in relations:
                db.session.delete(relation)
            db.session.commit()
            user = User.query.filter_by(id=current_user.id).first()
            logout_user()
            db.session.delete(user)
            db.session.commit()
            flash('Contul dumneavoastra a fost sters!')
            return redirect(url_for('index'))
        app.logger.info('1')
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(first_name=form.first_name.data, last_name=form.last_name.data, CNP=current_user.CNP,
                        email=form.email.data, password=hashed_password, role=current_user.role, is_active=1, is_deleted=0)
        old_user = User.query.filter_by(id=current_user.id).first()
        print(old_user)
        logout_user()
        db.session.delete(old_user)
        db.session.commit()
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        return redirect(url_for('dashboard'))
    return render_template('change_info.html', curr_urs_role=current_user.role, form=form, admin=0)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    logged_in = False
    user_id = -1
    curr_usr_role = -1
    user_notif = ""
    if current_user.is_authenticated:
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
        logged_in = True
        user_id = current_user.id
        curr_usr_role = curr_usr_role
        user_notif = 'Datele contului Dvs. vor fi asignate mesajului!'
    if form.validate_on_submit():
        new_request = ContactRequest(patient_id=user_id, first_name=form.first_name.data, datetime=datetime.datetime.now(), last_name=form.last_name.data, email=form.email.data, message=form.message.data, closed=0)
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('contact.html', form=form, user_notif=user_notif, logged_in=logged_in, curr_usr_role=curr_usr_role)


@app.route('/adauga_pacient', methods=['GET', 'POST'])
@login_required
def assign_patient():
    if current_user.role == 'Patient':
        flash('Nu aveți acces la această pagină!')
        return redirect(url_for('dashboard'))
    form = AssignPatientForm()
    if form.validate_on_submit():
        patient = User.query.filter_by(email=form.email.data).first()
        if patient.role == 'Doctor':
            flash("Nu puteti adauga un medic in lista de pacienti!")
            return render_template('adauga_pacient.html', form=form)

        if patient and patient.CNP == form.CNP.data:
            if AssignedPatients.query.filter_by(doctor_id=current_user.id, patient_id=patient.id).first():
                flash("Acest pacient este deja în lista dumneavoastră!")
                return render_template('adauga_pacient.html', form=form)

            new_assign = AssignedPatients(doctor_id=current_user.id, patient_id=patient.id, pending=1)
            db.session.add(new_assign)
            db.session.commit()
            return redirect(url_for('dashboard'))

        flash("Username sau email incorect")
        return render_template('adauga_pacient.html', form=form)

    return render_template('adauga_pacient.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Doctor':
        list = AssignedPatients.query.filter_by(doctor_id=current_user.id).order_by(AssignedPatients.pending.desc())
        assigned_patients = []
        pending = []
        for patient in list:
            assigned_patients.append(User.query.filter_by(id=patient.patient_id).first())
            pending.append(patient.pending == 1)
        return render_template('dashboard.html', patients=assigned_patients, pending=pending, curr_usr_role=current_user.role)

    list = AssignedPatients.query.filter_by(patient_id=current_user.id).order_by(AssignedPatients.pending.desc())
    assigned_doctors = []
    pending_doctors = []
    for invitation in list:
        if invitation.pending == 1:
            pending_doctors.append(User.query.filter_by(id=invitation.doctor_id).first())
        else:
            assigned_doctors.append(User.query.filter_by(id=invitation.doctor_id).first())
    device = Device.query.filter_by(user_id=current_user.id).first()
    device_key = 0
    if device:
        device_key = device.device_key
    return render_template('dashboard.html', device_key=device_key, assigned_doctors=assigned_doctors, pending_doctors=pending_doctors, curr_usr_role=current_user.role)


@app.route('/perform_action_on_user/<action>/<user_id>')
@login_required
def perform_action_on_user(action, user_id):
    if current_user.role != 'Admin':
        flash('Nu aveți acces la pagina căutată!')
        redirect(url_for('dashboard'))
    user = User.query.filter_by(id=user_id).first()
    if action == 'Delete':
        user.is_deleted = 1
        db.session.commit()
        flash('Contul utilizatorului ' + user.last_name + ' cu id-ul ' + str(user.id) + ' a fost marcat ca sters')
    elif action == 'Activate':
        user.is_active = 1
        db.session.commit()
        flash('Contul utilizatorului ' + user.last_name + ' cu id-ul ' + str(user.id) + ' a fost activat')
    elif action == 'Deactivate':
        user.is_active = 0
        db.session.commit()
        flash('Contul utilizatorului ' + user.last_name + ' cu id-ul ' + str(user.id) + ' a fost dezactivat')
    elif action == 'Recover':
        user.is_deleted = 0
        db.session.commit()
        flash('Contul utilizatorului ' + user.last_name + ' cu id-ul ' + str(user.id) + ' a fost recuperat')

    return redirect(url_for('view_all_users'))


@app.route('/modify_user_info/<user_id>', methods=['GET', 'POST'])
@login_required
def modify_user_info(user_id):
    if current_user.role != 'Admin':
        flash('Nu aveți acces la pagina căutată!')
        redirect(url_for('dashboard'))
    user = User.query.filter_by(id=user_id).first()
    form = ModifyUserInfoForm(first_name=user.first_name, last_name=user.last_name,
                              email=user.email, cnp=user.CNP, role=user.role)

    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.CNP = form.cnp.data
        user.email = form.email.data
        user.role = form.role.data
        app.logger.info(form.role.data)
        db.session.commit()
        return redirect(url_for('view_all_users'))
    return render_template('change_info.html', user_id=user.id, curr_urs_role=current_user.role, form=form, admin=1)


@app.route('/resolve_request', methods=['GET', 'POST'])
@login_required
def resolve_request():
    if current_user.role != 'Admin':
        flash('Nu aveți acces la pagina căutată!')
        redirect(url_for('dashboard'))
    request_form = request.form
    request_id = list(request_form.keys())[0]
    text = list(request_form.values())[0]
    resolved_request = ContactRequest.query.filter_by(id=request_id).first()
    resolved_request.admin_note = text
    resolved_request.closed = 1
    resolved_request.closed_datetime = datetime.datetime.now()
    db.session.commit()
    return redirect(url_for('dashboard_admin'))

@app.route('/dashboard_admin')
@login_required
def dashboard_admin():
    if current_user.role != 'Admin':
        flash('Nu aveți acces la pagina căutată!')
        redirect(url_for('dashboard'))
    new_requests = ContactRequest.query.filter_by(closed=0)
    return render_template('dashboard_admin.html', new_requests=new_requests)

@app.route('/view_users')
@login_required
def view_all_users():
    if current_user.role != 'Admin':
        flash('Nu aveți acces la pagina căutată!')
        redirect(url_for('dashboard'))
    users = User.query.filter(User.id != current_user.id).order_by(User.is_deleted.asc(), User.role.asc())
    return render_template('view_users.html', users=users, curr_usr_id=current_user.id)


def create_plot(data):
    img = BytesIO()
    timestamp, heading, pitch, roll, x_acc, y_acc, z_acc, multiplied_x_acc, multiplied_vertical_acc, stab_angle_x, mean_angle = [], [], [], [], [], [], [], [], [], [], []

    content = data.split('\n')

    for line in content[:-1]:
        words = line.split()
        print(words)
        x = float(words[1])
        if x < 30:
            x += 360
        x -= 360
        timestamp.append(words[0])
        heading.append(x)
        pitch.append(words[2])
        roll.append(words[3])
        x_acc.append(-1 * float(words[4]))
        y_acc.append(words[5])
        z_acc.append(words[6])
        multiplied_x_acc.append(float(words[7]))
        multiplied_vertical_acc.append(words[8])
        stab_angle_x.append(float(words[9]) - 90)
        x = float(words[11])
        if x < 40:
            x += 360
        x -= 360
        mean_angle.append(x)
    plt.rcParams["figure.figsize"] = (10, 4)
    # plt.plot(heading,  label = 'unghiul de giratie')
    plt.plot(mean_angle, label='media ultimelor 30 de citiri ale unghiurilor de giratie')
    plt.plot(multiplied_x_acc, label='magnitudinea accelerației liniare pe axa X')

    plt.plot(stab_angle_x, label='unghiul de stabilizare')
    plt.ylabel("Măsura unghiului")
    plt.xlabel("Numărul iteratiei")
    plt.legend()
    plt.savefig(img, format='png')
    plt.close()
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode('utf8')
    return plot_url


@app.route('/view_patient/<patient_id>', methods=['GET', 'POST'])
@login_required
def view_patient(patient_id):
    if current_user.role == 'Doctor':
        data = Stat.query.filter_by(patient_id=patient_id).first().data
        url_plot = create_plot(data)
        form = NoteForm()
        assigned_user = AssignedPatients.query.filter_by(doctor_id=current_user.id, patient_id=patient_id).first()
        notes = Note.query.filter_by(relation_id=assigned_user.id).order_by(Note.datetime.desc())

        app.logger.info('aiciiiii')

        app.logger.info(notes)
        if not assigned_user:
            flash('Nu aveți acces la această pagină!')
            return redirect(url_for('dashboard'))
        if form.validate_on_submit():
            new_note = Note(relation_id=assigned_user.id, datetime=datetime.datetime.now().replace(microsecond=0), text=form.note_text.data)
            db.session.add(new_note)
            db.session.commit()
        patient = User.query.filter_by(id=patient_id).first()
        return render_template('view_patient.html', form=form, curr_usr_role=current_user.role, patient=patient, notes=notes, url_plot=url_plot)
    else:
        assigned_user = AssignedPatients.query.filter_by(doctor_id=patient_id, patient_id=current_user.id).first()
        if not assigned_user:
            flash('Nu aveți acces la această pagină!')
            return redirect(url_for('dashboard'))
        patient = User.query.filter_by(id=patient_id).first()
        return render_template('view_patient.html', curr_usr_role=current_user.role, patient=patient)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/adauga_device', methods=['GET', 'POST'])
@login_required
def add_device():
    if current_user.role == 'Doctor':
        flash('Nu aveți acces! Această pagină este destinată pacienților!')
        return redirect(url_for('dashboard'))
    form = DeviceForm()
    if Device.query.filter_by(user_id=current_user.id).first():
        flash('Folosiți deja un device! Eliminați-l din lista dumneavoastră pentru a putea înregistra unul nou')
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        device = Device.query.filter_by(device_key=form.device_key.data).first()
        if device:
            if device.user_id != -1:
                flash('Acest device este deja folosit de alt utilizator!')
                return render_template('adauga_device.html', form=form)
            device.user_id = current_user.id
            db.session.commit()
            return redirect(url_for('dashboard'))

        flash('Cod Gresit! Acest device nu exista')
    return render_template('adauga_device.html', form=form)


@app.route('/delete_device')
@login_required
def delete_device():
    if current_user.role == 'Doctor':
        flash('Nu aveți acces! Această pagină este destinată pacienților!')
        return redirect(url_for('dashboard'))
    device = Device.query.filter_by(user_id=current_user.id).first()
    if device:
        dev_id = device.device_key
        device.user_id = -1
        db.session.commit()
        flash('Device-ul cu cheia ' + str(dev_id) + ' a fost șters din lista dumneavoastră!')
        return redirect(url_for('dashboard'))
    else:
        flash('Nu puteți accesa această funcție doarece nu utilizați niciun device!')
        return redirect(url_for('dashboard'))


@app.route('/gestionare_cereri/<doctor_id>/<accepted>')
@login_required
def gestionare_cereri(doctor_id, accepted):
    if accepted == "1":
        invitation = AssignedPatients.query.filter_by(doctor_id=doctor_id, patient_id=current_user.id).first()
        invitation.pending = 0
        db.session.commit()
    else:
        invitation = AssignedPatients.query.filter_by(doctor_id=doctor_id, patient_id=current_user.id).first()
        db.session.delete(invitation)
        db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/stergere_relatie_medic_pacient/<id_user>')
@login_required
def stergere_relatie_medic_pacient(id_user):
    if current_user.role == 'Doctor':
        invitation = AssignedPatients.query.filter_by(doctor_id=current_user.id, patient_id=id_user).first()
        db.session.delete(invitation)
        db.session.commit()
    else:
        invitation = AssignedPatients.query.filter_by(doctor_id=id_user, patient_id=current_user.id).first()
        db.session.delete(invitation)
        db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host= '192.168.100.151')