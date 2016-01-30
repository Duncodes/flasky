import md5

from flask import Flask,render_template,request,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form

from werkzeug.security import check_password_hash
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import Required,Email,EqualTo,Length
import os


app = Flask(__name__)

app.config['SECRET_KEY'] = 'spodifuyggdjkslfjihugweyftshdjkflnkjgfehgudiyegvcbhjv'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:duncan@localhost/flasky'

#app.config['DATA']='/home/duncan/databases'

db = SQLAlchemy(app)

bootstrap = Bootstrap(app)


name="Login/register"


#class for database
class Questions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    question = db.Column(db.String(500))
    answer = db.column(db.String(500))


    def __init__(self,id,title,question,answer):
        self.id=id
        self.title = title
        self.question = question
        self.answer = answer


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    password = db.Column(db.String(200))

    def __init__(self,name,email,passwd):
        self.name = name
        self.email = email
        self.password = hash_pass(passwd)




class CreateQuestion(Form):
    title = StringField('Title', validators=[Required()])
    question = StringField('Question', validators=[Required()])
    answer = StringField('Answer', validators=[Required()])
    submit = SubmitField('Submit')

class Register(Form):
    name = StringField('Name', validators=[Required()])
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required(),Length(min=6),EqualTo('confirm', message="Password must match")])
    confirm=PasswordField('Repeat password')
    submit = SubmitField('Submit')


class Login(Form):
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required(),Length(min=6)])
    submit = SubmitField('Submit')


def hash_pass(password):
        """
            Return the md5 hash of the password+salt
        """
        salted_password = str(password) + str(app.secret_key)
        return md5.new(salted_password).hexdigest()

@app.route('/')
def index():
    return render_template('index.html',name=name)


@app.route('/createquestion', methods=['GET', 'POST'])
def createquestion():
    form=CreateQuestion()
    if request.method == 'GET':
        return render_template('createquestion.html', form=form)
    elif request.method == 'POST':
        if form.validate_on_submit():
            title=form.title.data
            question =form.question.data
            answer =form.answer.data
            kamau=Questions(id,title,question,answer)
            db.session.add(kamau)
            db.session.commit()
            return render_template('createdquestion.html', question=question)




@app.route('/login',methods=['GET','POST'])
def login():
    formlogin = Login()
    if request.method == 'GET':
        return render_template('login.html',form = formlogin)
    elif request.method == 'POST':
        if formlogin.validate_on_submit():
            user= Users.query.get('email')
            print(user)
            if user:
                if check_password_hash(user.password, formlogin.password.data):
                    db.session.add(user)
                    #useremail = formlogin.email.data
                    #password = formlogin.password.data
                    #if useremail==Users.query.filter_by(email=useremail ).first():
                    return redirect(url_for('index'))
        return render_template('login.html',form=formlogin)
@app.route('/register', methods=['GET','POST'])
def register():
    formregister=Register()
    if request.method == "GET":
        return render_template('register.html', form=formregister)

    elif request.method == "POST":
        if formregister.validate_on_submit():
            name = formregister.name.data
            email  = formregister.email.data
            password = formregister.password.data
            kamau = Users(name,email,password)
            db.session.add(kamau)
            db.session.commit()

            return redirect(url_for('login'))

        else:
            return render_template('register.html' ,form=formregister)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
