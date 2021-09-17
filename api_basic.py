from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps

from werkzeug.utils import redirect

app = Flask(__name__)

SECRET_KEY = 'SECRET_KEY'

app.config[SECRET_KEY] = 'thisisthesecretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        print(token)
        if not token:
            return jsonify({'message' : 'token is missing'}), 403

        try:
            data = jwt.decode(token, app.config[SECRET_KEY],algorithms=["HS256"])
        except:
            return jsonify({'message' : 'token is invalid'}), 403
        
        return f(*args, **kwargs)
    return decorated



@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Anyone can view this!'})



@app.route('/protected')
@token_required
def protected():
    return jsonify({'message' : 'Only people with a valid token can view this!'})



@app.route('/protected_without_decorator')
def protected2():
    token = request.args.get('token')
    print(token)
    if not token:
        return jsonify({'message' : 'token is missing'}), 403
    try:
        data = jwt.decode(token, app.config[SECRET_KEY],algorithms=["HS256"])
    except:
        return jsonify({'message' : 'token is invalid'}), 403

    return jsonify(data)



@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'secret':
        token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config[SECRET_KEY], algorithm="HS256")
        print(jwt.decode(token, app.config[SECRET_KEY],algorithms=["HS256"]))
        return token
        

    return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})

if __name__ == "__main__":
    app.run(debug = True)