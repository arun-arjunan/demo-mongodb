from flask import Flask, render_template, url_for, request, session, redirect
from flask_pymongo import PyMongo
import bcrypt

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.config['MONGO_DBNAME'] = 'logindb'
app.config['MONGO_URI'] = 'mongodb+srv://Arun:arun123@gettingstarted-pxlw3.mongodb.net/logindb'
mongo = PyMongo(app)

app.config.from_pyfile('config.cfg')
mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')

@app.route('/')
def index():
    if 'username' in session:
        return 'You are logged in as ' + session['username']

    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name' : request.form['username']})

    if login_user:
        if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    return 'Invalid username/password combination'

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name' : request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            strhashpass = hashpass.decode('utf8')
            users.insert({'name' : request.form['username'], 'email' : request.form['email'], 'password' : strhashpass})
            session['username'] = request.form['username']
            #return redirect(url_for('index'))
            
            email = request.form['email']
            token = s.dumps(email, salt='email-confirm')
            msg = Message('Confirm Email', sender='arun.arjunan87@gmail.com', recipients=[email])
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = 'Your link is {}'.format(link)
            mail.send(msg)
            return '<h2>Check your mailbox and click the link to verify your signing up process.</h2>'.format(email, token)
        
        return 'That username already exists!'

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=300)
    except SignatureExpired:
        return '<h2>The token is expired!</h2>'
    return '<h2>Congratulations! Your sign up has been successfully completed.</h2>'

if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)