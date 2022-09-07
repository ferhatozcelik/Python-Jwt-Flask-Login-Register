from flask import jsonify, make_response
import jwt
from datetime import datetime, timedelta

import constants


def resultdata(errorcode, message, result, key):
    return make_response(jsonify({'code': errorcode, 'message': message, 'result': result, 'key': key}), errorcode)


def generatortoken():
    return jwt.encode({'ACCESS_KEY': constants.ACCESS_KEY, 'exp': datetime.utcnow() + timedelta(minutes=5)},
                      constants.APP_SECRET_KEY)


def localdecodetoken():
    return jwt.decode(generatortoken(), constants.APP_SECRET_KEY, "HS256")


def isverifyjwttoken(access_token):
    try:
        dec = jwt.decode(access_token, constants.APP_SECRET_KEY, "HS256")
        if dec is not None and dec['ACCESS_KEY'] is not None:
            if dec['ACCESS_KEY'] == localdecodetoken()['ACCESS_KEY']:
                return True
            else:
                return False
        else:
            return False
    except Exception:
        return False


