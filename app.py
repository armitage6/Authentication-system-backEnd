from flask import Flask, request, jsonify
from models import db, User
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['JWT_SECRET_KEY'] = 'super-secreta'
db.init_app(app)

migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route("/")
def home():
    return "Hello SQLAlchemy y Flask"


@app.route("/users", methods=["POST"])
def create_user():
    user = User()
    user.username = request.json.get("username")
    user.age = request.json.get("age")

    password = request.json.get("password")
    password_hash = generate_password_hash(password)
    user.password = password_hash

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'msg': 'User have been created'
    }), 200

@app.route('/login', methods={'POST'})
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user is not None:
        is_valid = check_password_hash(user.password, password)
        if is_valid:
            access_token = create_access_token(identity=username)
            return jsonify({
                'token': access_token
            }), 200
    else:
        return jsonify({
            'msg': 'user does not exist'
        }), 400    


@app.route("/users/list", methods=["GET"])
@jwt_required()
def get_users():
    users = User.query.all()
    result = []
    for user in users:
        result.append(user.serialize())
    return jsonify(result)


@app.route("/users/<int:id>", methods=["PUT", "DELETE"])
def update_user(id):
    user = User.query.get(id)
    if user is not None:
        if request.method == "DELETE":
            db.session.delete(user)
            db.session.commit()

            return jsonify("Eliminado"), 204
        else:
            user.age = request.json.get("age")

            db.session.commit()

            return jsonify("Usuario actualizado"), 200

    return jsonify("Usuario no encontrado"), 418


if __name__ == '__main__':
    app.run(host="localhost", port="8080")
