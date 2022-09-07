from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import constants
import tools

app = Flask(__name__)

app.config['SECRET_KEY'] = constants.APP_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = constants.DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
base_path = '/api'
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'USERS'
    USER_ID = db.Column(db.Integer, primary_key=True)
    USER_FULLNAME = db.Column(db.String(100))
    USER_EMAIL = db.Column(db.String(50))
    PASSWORD = db.Column(db.String(500))
    USERNAME = db.Column(db.String(500))
    CREATE_DATE = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    LAST_LOGIN_DATE = db.Column(db.DateTime)
    USER_IMAGE = db.Column(db.LargeBinary)


def ApiKeyVerify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
            if token is not None:
                if token == constants.API_KEY:
                    return f(*args, **kwargs)
                else:
                    return tools.resultdata(401, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')
            else:
                return tools.resultdata(401, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')
        else:
            return tools.resultdata(404, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')

    return decorated


def SessionKeyVerify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'access_token' in request.headers:
            access_token = request.headers['access_token']
            if access_token is not None:
                if tools.isverifyjwttoken(access_token):
                    return f(*args, **kwargs)
                else:
                    return tools.resultdata(401, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')
            else:
                return tools.resultdata(401, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')
        else:
            return tools.resultdata(404, constants.FAILED_MESSAGE, 'Token is missing', 'TOKEN_IS_MISSING')

    return decorated


@app.route(base_path + '/', methods=['GET'])
@app.route('/', methods=['GET'])
def init():
    return 'StoryU API Starting...'


@app.route(base_path + '/signup', methods=['POST'])
@ApiKeyVerify
def signup():
    data = request.json

    username, fullname, email = data['username'], data['fullname'], data['email']
    password = data['password']

    isEmailCheck = User.query.filter_by(USER_EMAIL=email).first()

    isUsernameCheck = User.query.filter_by(USERNAME=username).first()

    if not isEmailCheck:
        if not isUsernameCheck:
            user = User(
                USER_FULLNAME=fullname,
                USER_EMAIL=email,
                PASSWORD=generate_password_hash(password),
                USERNAME=username)
            db.session.add(user)
            db.session.commit()
            return tools.resultdata(201, constants.SUCCESS_MESSAGE, 'Successfully Registered.', 'SUCCESS_REGISTERED')
        else:
            return tools.resultdata(404, constants.FAILED_MESSAGE, 'Username already exists. Please Log in.', 'USERNAME_EXISTS')
    else:
        return tools.resultdata(404, constants.FAILED_MESSAGE, 'Email already exists. Please Log in.', 'EMAIL_EXISTS')


@app.route(base_path + '/login', methods=['POST'])
@ApiKeyVerify
def login():
    auth = request.json

    if not auth or not auth['email'] or not auth['password']:
        return tools.resultdata(404, constants.FAILED_MESSAGE, 'Login username and password required',
                                'COULD_NOT_VERIFY')

    user = User.query.filter_by(USER_EMAIL=auth['email']).first()

    if not user:
        return tools.resultdata(404, constants.FAILED_MESSAGE, 'User does not exist', 'COULD_NOT_VERIFY')

    if check_password_hash(user.PASSWORD, auth['password']):
        User.query.filter_by(USER_EMAIL=auth['email']).update(dict(LAST_LOGIN_DATE=datetime.utcnow()))
        db.session.commit()

        user = User.query.filter_by(USER_EMAIL=auth['email']).first()

        return tools.resultdata(200, constants.SUCCESS_MESSAGE, {'userid': user.USER_ID,
                                                                 'userfullname': user.USER_FULLNAME,
                                                                 'email': user.USER_EMAIL,
                                                                 'username': user.USERNAME,
                                                                 'last_login_date': user.LAST_LOGIN_DATE,
                                                                 }, 'LOGIN_VERIFYED')

    return tools.resultdata(404, constants.FAILED_MESSAGE, 'Wrong Password', 'WRONG_PASSWORD')


@app.route(base_path + '/accesstoken', methods=['POST'])
@ApiKeyVerify
def accesstoken():
    return tools.resultdata(200, constants.SUCCESS_MESSAGE, {'access_token': tools.generatortoken()},
                            'CRAETE_ACCESS_TOKEN')


if __name__ == "__main__":
    app.run()
