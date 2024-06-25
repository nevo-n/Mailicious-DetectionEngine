import os
import json
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from src.DBHandler import DBHandler
from DetectionEngine.DetectionPipeline import analyze_mail
from dotenv import load_dotenv

load_dotenv()
# read secret key from .env
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

app = Flask("Mailicious")

# Configure your JWT secret key
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not DBHandler().verify_login(username, password):
      return jsonify({"msg": "Bad username or password"}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/analyze', methods=['POST'])
@jwt_required()
def send_data_for_analysis():
   customer_id = get_jwt_identity()
   verdict = analyze_mail(customer_id, json.loads(request.data))
   if verdict:
      return jsonify({'verdict': f"{verdict}"}), 200
   else:
      return jsonify({'error': "internal"}), 500


if __name__ == '__main__':
    app.run(debug=True)