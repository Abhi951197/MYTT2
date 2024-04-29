from flask import Flask, render_template, request, jsonify, url_for, redirect, session,flash
from flask_sqlalchemy import SQLAlchemy
from flask_dropzone import Dropzone
from sqlalchemy.ext.declarative import declarative_base
import os
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy import desc
import sqlalchemy
from sqlalchemy import MetaData,create_engine,Engine,event
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import sqlalchemy.exc
from collections import defaultdict
import re



basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@127.0.0.1/tt2'
app.config['SECRET_KEY'] = 'this_is_a_secret_key'
Base = declarative_base()
engine = create_engine('mysql://root:root@127.0.0.1/tt2')


bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



db = SQLAlchemy(app)


class EnrolledOptions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(255))
    selected_options = db.Column(db.String(255))
    date = db.Column(db.String(40))
    



class slots(db.Model):
    __tablename__ = 'slots'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_slot = db.Column(db.String(255), nullable=False)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False)
    user = relationship("User", back_populates="user_slots")
    f_name=db.Column(db.String(80))
    
    def __repr__(self) -> str:
        return '<Name %r>' % self.slot_data
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    user_slots = db.relationship('slots', backref='owner', lazy=True)
    is_active = db.Column(db.Boolean, default=True)  # Add this line

    def __repr__(self):
        return f'<User {self.email}>'
    def is_active(self):
        return self.active  
    def get_id(self):
        return str(self.id) 
    @property
    def is_authenticated(self):
        return True 
    @property
    def is_anonymous(self):
        return False 

class KGDSlotEnrollment(db.Model):
    __tablename__ = 'KGDSlotEnrollment'
    id = db.Column(db.Integer, primary_key=True)
    slot_details = db.Column(db.String(255), nullable=False)  # Slot details: s32+s33:KGD Thursday 9.00 am to 10.00 am E101 & KGD Thursday 10.00 am to 11.00 am E101
    user_email = db.Column(db.String(80), nullable=False)  # User's email

    def __repr__(self):
        return f'<KGDSlotEnrollment {self.slot_details} - {self.user_email}>'


class SlotData(db.Model):
    __tablename__ = 'slotdata'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    f_name=db.Column(db.String(80))
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False) 
    
class Subject(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sno = db.Column(db.Integer, primary_key=True)
    Level = db.Column(db.String(80), nullable=False)
    Course = db.Column(db.String(80), nullable=False)   
    Semester = db.Column(db.String(80), nullable=False)
    Syllabus = db.Column(db.String(80), nullable=False)

class CNT(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'CNT'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False) 
    f_name=db.Column(db.String(255))
    
class CNT_slots(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'CNT_slots'
    subject_slot_id = db.Column(db.Integer, primary_key=True)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False)
    f_name = db.Column(db.String(255))
    print(day)
    
class EM4(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'EM4'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False)
    f_name=db.Column(db.String(255))


class EM4_slots(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'EM4_slots'
    subject_slot_id = db.Column(db.Integer, primary_key=True)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False)  
    f_name=db.Column(db.String(255))
   
class OST(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'OST'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False) 
    f_name=db.Column(db.String(80))

class OST_slots(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'OST_slots'
    subject_slot_id = db.Column(db.Integer, primary_key=True)
    slot_data = db.Column(db.String(255), nullable=False)
    day = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(80), nullable=False)   

    f_name=db.Column(db.String(80))

class slot_enroll(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __tablename__ = 'slot_enroll'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    selected_options = db.Column(db.String(255), nullable=False)
    date = db.Column(db.String(40), nullable=False)
    user = db.Column(db.String(255), nullable=False)
    f_name = db.Column(db.String(255))
    day = db.Column(db.String(20))
    enrolled_users = db.Column(db.Integer, default=0)


class UserData(db.Model):
    __tablename__ = 'UserData'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegisterForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email id already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=80)], render_kw={"placeholder": "Enter your Email id"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

dropzone = Dropzone(app)
selected_options = {}

@app.route('/templates/index.html', methods=['POST', 'GET'])
def upload():
    if current_user.is_authenticated:
        # Fetch data from the database
        posts = slots.query.all()
        slot_data_entries = SlotData.query.all()
        subjects = CNT.query.all()
        Cnl = CNT_slots.query.all()
        EM4_sub = EM4.query.all()
        EM4slots = EM4_slots.query.all()
        OS_sub = OST.query.all()
        OSTslots = OST_slots.query.all()
        enrolled_options = slot_enroll.query.filter_by(user=current_user.email).first()

        # Create a dictionary to store enrollment status of each slot
        enrollment_status = {}
        # Check if each slot has reached its enrollment limit
        for slot in posts:
            # Count the number of users already enrolled for the current slot
            enrolled_users_count = slot_enroll.query.filter(slot_enroll.selected_options.contains(slot.slot_data)).count()
            print("enroll",enrolled_users_count)
            availability = 2 - enrolled_users_count
            print("availability",availability)
            # Store the availability in the enrollment_status dictionary
            enrollment_status[slot.id] = availability if availability >= 0 else 0
            print("enrollment_status",enrollment_status[slot.id])
            # Determine if the slot is enabled or disabled based on the enrollment limit
            if enrolled_users_count >= 2:
                enrollment_status[slot.id] = False  # Disable the slot
            else:
                enrollment_status[slot.id] = True  # Enable the slot

        selected_options = {}

        refresh = False  # Flag to indicate if page is being refreshed

        if request.method == 'POST':
            selected_option = request.form.get('selected_option')
            if selected_option:
                if selected_options.get(selected_option):
                    return jsonify({'message': 'Option already selected!'})
                else:
                    selected_options[selected_option] = True
            for key, f in request.files.items():
                if key.startswith('file'):
                    f.save(os.path.join(app.config['UPLOADED_PATH'], f.filename))

            # Check if max enrollment limit has been reached
            if enrolled_options and enrolled_options.enrolled_users >= 2:
                flash('Maximum enrollment limit has been reached for the selected options.', 'error')
                return redirect(url_for('upload'))

            return redirect(url_for('enroll'))
        else:
            refresh = True  # Set refresh flag to True when page is loaded

            # Pass the enrollment status dictionary and refresh flag to the template context
            return render_template('index.html', enrolled_options=enrolled_options, selected_options=selected_options, EM4_sub=EM4_sub, EM4slots=EM4slots, CNT_slots=CNT_slots, OS_sub=OS_sub, OSTslots=OSTslots, Cnl=Cnl, slots_data=posts, slot_data_entries=slot_data_entries, subjects=subjects, button_id="menu2", enrollment_status=enrollment_status, refresh=refresh)
    else:
        return redirect(url_for('login'))

    
@app.route('/enroll', methods=['POST'])
@login_required
def enroll():
    if request.method == 'POST':
        selected_options = request.form.getlist('selected_options[]')

        if selected_options:
            slot_enroll.query.filter_by(user=current_user.email).delete()

            for option in selected_options:
                # Count the number of users already enrolled for the current option
                enrolled_users_count = slot_enroll.query.filter(slot_enroll.selected_options.contains(option)).count()
                print("enrolled_users_count",enrolled_users_count)
                if enrolled_users_count >= 2:
                    flash('Maximum enrollment limit reached for some options. Please choose other options.', 'error')
                    return redirect(url_for('upload'))

                table_name = determine_table_name(option)
                if table_name:
                    # Fetch f_name from the respective table
                    f_name = fetch_f_name(table_name, option)
                    if f_name is not None:
                        try:
                            # Check if the user is already enrolled twice for the selected option
                            if is_enrolled_twice(current_user.email, option):
                                flash(f'You are already enrolled twice for the slot {option}. You cannot enroll again.', 'error')
                            else:
                                # Delete previous record if user is already enrolled
                                previous_enrollment = slot_enroll.query.filter_by(user=current_user.email, selected_options=option).first()
                                if previous_enrollment:
                                    db.session.delete(previous_enrollment)
                                    db.session.commit()

                                # Proceed with enrolling the user for selected options
                                new_enrollment = slot_enroll(
                                    selected_options=option,
                                    date=datetime.now().strftime('%Y-%m-%d'),
                                    user=current_user.email,
                                    f_name=f_name,
                                    enrolled_users=1
                                )
                                db.session.add(new_enrollment)
                                db.session.commit()
                                flash('Enrollment successful!', 'success')
                        except Exception as e:
                            db.session.rollback()
                            flash('Error occurred during enrollment.', 'error')
                            print(e)
                    else:
                        flash(f'Error: f_name not found for selected option {option}', 'error')
                        
                else:
                    flash(f'Error: Table name not found for selected option {option}', 'error')

            return redirect(url_for('upload'))
        else:
            flash('No options selected!', 'error')
            return redirect(url_for('upload'))




def determine_table_name(selected_option):
    if "S12+S13:KGD" in selected_option:
        return "CNT"
    if "S32+S33:KGD" in selected_option:
        return "slots"
    elif any(pattern in selected_option for pattern in ["S04+S05:KGD", "S14+S15:KGD", "S34+S35:KGD", "S44+S45:KGD"]):
        return "cnt_slots"
    elif "S34+S35+S44:USK" in selected_option:
        print("dont mdm",selected_option)
        return "EM4"
    elif any(pattern in selected_option for pattern in ["S04+S05+S24:SBP", "S22+S23+S46:USK", "S16+S26+S27:SBP"]):
        return "EM4_slots"
    elif "S16+S17:RSR" in selected_option:
        return "ost"
    elif any(pattern in selected_option for pattern in ["S32+S33:RSR", "S16+S17:SNA", "S14+S15:SNA"]):
        return "ost_slots"
    elif "S46+S47:KGD" in selected_option:
        return "SlotData"
    else:
        return None
    
def fetch_f_name(table_name, selected_option):
    if table_name == "CNT":
        cnt_entry = CNT.query.filter_by(slot_data=selected_option).first()
        if cnt_entry:
            return cnt_entry.f_name
    elif table_name == "cnt_slots":
        cnt_slots_entry = CNT_slots.query.filter_by(slot_data=selected_option).first()
        if cnt_slots_entry:
            return cnt_slots_entry.f_name
    elif table_name == "EM4":
        em4_entry = EM4.query.filter_by(slot_data=selected_option).first()
        if em4_entry:
            return em4_entry.f_name
    elif table_name == "EM4_slots":
        em4_slots_entry = EM4_slots.query.filter_by(slot_data=selected_option).first()
        if em4_slots_entry:
            return em4_slots_entry.f_name
    elif table_name == "ost":
        ost_entry = OST.query.filter_by(slot_data=selected_option).first()
        if ost_entry:
            return ost_entry.f_name
    elif table_name == "ost_slots":
        ost_slots_entry = OST_slots.query.filter_by(slot_data=selected_option).first()
        if ost_slots_entry:
            return ost_slots_entry.f_name
    elif table_name == "SlotData":
        slotdata_entry = SlotData.query.filter_by(slot_data=selected_option).first()
        if slotdata_entry:  
            return slotdata_entry.f_name
    elif table_name == "slots":
        slots_entry=slots.query.filter_by(slot_data=selected_option).first()
        if slots_entry:
            return slots_entry.f_name
    return None



def is_enrolled_twice(user_email, selected_option):
    # Count the number of times the user is enrolled for the selected option
    enrolled_count = slot_enroll.query.filter_by(user=user_email, selected_options=selected_option).count()
    # Return True if the user is enrolled twice, otherwise False
    return enrolled_count >= 2


        




@app.route('/view_enrolled_options')
@login_required
def view_enrolled_option():
    # Fetch all enrolled options from the database for the current user
    enrolled_options = slot_enroll.query.filter_by(user=current_user.email).all()
    # Pass the enrolled options data to the template
    return render_template('enroll.html', enrolled_options=enrolled_options, enrolled_users=enrolled_options[0].enrolled_users if enrolled_options else 0)





@app.route("/main")
@login_required
def main():
    entries = slots.query.filter_by(user_id=current_user.id).all()
    posts = slots.query.all() 
    return render_template('main.html',entries = entries, slots_data=posts)


def main1():
    subjects = CNT.query.all()
    Cnl = CNT_slots.query.all() 
    print(subjects)
    return render_template('main.html', subjects=subjects, Cnl=Cnl)

def main2():
    EM4_sub = EM4.query.all()
    EM4slots = EM4_slots.query.all()
    print(EM4_sub)
    return render_template('main.html', EM4_sub=EM4_sub, EM4slots=EM4slots)    

def main3():
    OS_sub = OST.query.all()
    OSTslots = OST_slots.query.all()
    print(OS_sub)
    return render_template('main.html', OS_sub=OS_sub, OSTslots=OSTslots)    

@app.route('/delete_option', methods=['POST'])
@login_required
def delete_option():
    option_to_delete = request.form.get('option_to_delete')
    if option_to_delete in selected_options:
        del selected_options[option_to_delete]
        return render_template('index.html', selected_options=selected_options)
    else:
        return jsonify({'message': 'Option not found!'})

@app.route("/templates/subject.html", methods=['GET','POST'])
@login_required
def submit_subject():
    if request.method == 'POST':
        Level = request.form.get('dish')
        Course = request.form.get('course')
        Semester = request.form.get('sem')
        Syllabus = request.form.get('syllabus')

        print("Level:", Level)
        print("Course:", Course)
        print("Semester:", Semester)
        print("Syllabus:", Syllabus)
        if (Level == "UNDER GRADUATE" and (Course == "INFORMATION TECHNOLOGY" or Course == "COMPUTER ENGINEERING")
            and Semester == "SEMESTER IV" ):
            print("Redirecting to upload")
            entry = Subject(Level=Level, Course=Course, Semester=Semester, Syllabus=Syllabus)
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('upload'))      
        else:
            print("Rendering subject.html")
            return render_template('subject.html')
    else:
        return render_template('subject.html')



@app.route('/submit_data', methods=['POST'])
@login_required
def submit_data():
    if request.method == 'POST':
        selected_options = request.form['selected_options']
        day = request.form['day']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']
        slot = request.form['slot']
        faculty_room = re.search(r'(\w+) (\w+)', selected_options).groups()
        faculty = faculty_room[0]
        room = faculty_room[1]
        start_time = datetime.strptime(start_time_str, '%H:%M %p').time()
        end_time = datetime.strptime(end_time_str, '%H:%M %p').time()
        new_slot = slot_enroll(user=current_user.id, slot=slot, day=day, start_time=start_time, end_time=end_time, faculty=faculty, room=room)
        db.session.add(new_slot)
        db.session.commit()
        return redirect(url_for('upload'))

@app.route('/', methods=['GET', 'POST'])
def login():  
    if current_user.is_authenticated:
        return redirect('/main') 
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if is_new_user(user.email):
                    return redirect(url_for('main'))
                return redirect(url_for('main'))
    return render_template('login.html', form=form)

def is_new_user(email):
    # Query the database to check if the email exists
    existing_user = User.query.filter_by(email=email).first()
    # If the user exists, return False (not a new user), otherwise return True
    return existing_user is None



    # Create the tables in the new namespace

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.pop('user_email', None)  # Remove user's email from session
    return redirect(url_for('login'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)




@app.route('/main10')
def main10():
    # Render the subject page
    return render_template('main.html')

@app.route('/templates/timetable.html', methods=['GET'])
@login_required
def table():
    if current_user.is_authenticated:
        # Fetch only the slots belonging to the current user
        posts = slots.query.filter_by(user_id=current_user.id).all()
        slot_data_entries = SlotData.query.filter_by(user_id=current_user.id).all()
        subjects = CNT.query.filter_by(user_id=current_user.id).all()
        Cnl = CNT_slots.query.filter_by(user_id=current_user.id).all()
        EM4_sub = EM4.query.filter_by(user_id=current_user.id).all()
        EM4slots = EM4_slots.query.filter_by(user_id=current_user.id).all()
        OS_sub = OST.query.filter_by(user_id=current_user.id).all()
        OSTslots = OST_slots.query.filter_by(user_id=current_user.id).all()
        enrolled_options = slot_enroll.query.filter_by(user=current_user.email).all()
        print("enrollead",enrolled_options)
        selected_options = []

        # Pass the user variable to the template context
        return render_template('timetable.html',  
                               enrolled_options=enrolled_options,
                               selected_options=selected_options,
                               EM4_sub=EM4_sub, 
                               EM4slots=EM4slots, 
                               CNT_slots=CNT_slots, 
                               OS_sub=OS_sub, 
                               OSTslots=OSTslots, 
                               Cnl=Cnl, 
                               slots_data=posts, 
                               slot_data_entries=slot_data_entries, 
                               subjects=subjects, 
                               button_id="menu2",
                               user=current_user)  # Pass the current user to the template context
    else:
        return redirect(url_for('login'))
    
from collections import defaultdict

@app.route('/enroll1', methods=['GET'])
@login_required
def table1():
    if current_user.is_authenticated:
        # Fetch enrolled options for the current user
        enrolled_options = slot_enroll.query.filter_by(user=current_user.email).all()

        # Create a timetable dictionary to store selected options
        timetable = {
            "Monday": defaultdict(list),
            "Tuesday": defaultdict(list),
            "Wednesday": defaultdict(list),
            "Thursday": defaultdict(list),
            "Friday": defaultdict(list),
            "Saturday": defaultdict(list)
        }

        # Iterate over enrolled options and populate the timetable
        for option in enrolled_options:
            # Parse selected_options string to extract day, start time, and end time
            matches = re.findall(r'(\w+) (\d+\.\d+ [ap]m) to (\d+\.\d+ [ap]m)', option.selected_options)
            for match in matches:
                day = match[0]
                start_time = match[1]
                end_time = match[2]

                # Determine the time slot based on start time
                time_slot = f"{start_time} to {end_time}"

                # Append the selected option's f_name to the timetable dictionary for each time slot
                timetable[day][time_slot].append(option.f_name)

        # Pass timetable data to the template
        return render_template('enroll.html', timetable=timetable)

    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)