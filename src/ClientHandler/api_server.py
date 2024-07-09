import os
import json
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from src.DetectionEngine.DetectionPipeline import analyze_mail
from src.DBHandler.DBHandler import DBHandler
from dotenv import load_dotenv

app = Flask("Mailicious")

# load db info from .env file
load_dotenv()

JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY")
# Configure your JWT secret key
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
jwt = JWTManager(app)

# create DB handler
db_handler = DBHandler()

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # verify login credentials
    if not db_handler.verify_login(username, password):
      return jsonify({"msg": "Bad username or password"}), 401
    
    # create and return access token for further client operations
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/analyze', methods=['POST'])
@jwt_required()
def send_data_for_analysis():
   customer_id = get_jwt_identity()
   # analyze mail
   verdict = analyze_mail(json.loads(request.data))

   # return verdict accordingly
   if verdict in [True, False]:
      return jsonify({'verdict': f"{verdict}"}), 200
   else:
      return jsonify({'error': "internal"}), 500


if __name__ == '__main__':
    app.run(debug=True)