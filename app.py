            ########### IMPORTS ############
from flask import Flask, request, jsonify, make_response, send_from_directory, url_for
from flask_mail import Message,Mail
from flask_restful import Api,fields,Resource
from flask_swagger_ui import get_swaggerui_blueprint
#from routes import re
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import true,update
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
import jinja2
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
from functools import wraps
from dotenv import load_dotenv
import os
            ############### CONFIG ##################

#app=Flask(__name__)
app = Flask(__name__)
api=Api(app)


#name_space = app.namespace('main', description='Main APIs')

load_dotenv()
secret = os.getenv('secret_key')
sender1 = os.getenv('sender')
app.config['SECRET_KEY']=secret
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////home/cbnits/bookApi/library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config.from_pyfile('config.cfg')

template_dir=os.path.join(os.path.dirname(__file__),'templates')
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))

mail=Mail(app)

db = SQLAlchemy(app)
s= URLSafeTimedSerializer(app.config['SECRET_KEY'])


################################ DATABASE ######################################


class Users(db.Model):
     id = db.Column(db.Integer, primary_key=True)
     public_id = db.Column(db.Integer)
     name = db.Column(db.String(50))
     password = db.Column(db.String(50))
     admin = db.Column(db.Boolean)
     activate = db.Column(db.Boolean)


class Books(db.Model):
      book_id = db.Column(db.Integer , primary_key=True)
      book_name = db.Column(db.String(50))
      in_stock = db.Column(db.Boolean)


########################### FUNCTIONS ###############################

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-token' in request.headers:
         token = request.headers['x-access-token']

      if not token:
         return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
            return jsonify({'message': 'token is invalid'}),401

      return f(current_user, *args, **kwargs)
   return decorator

def check_email(mail):
   try:
    token= s.dumps(mail,salt='email-confirm')
    #mail = s.loads(token,salt='email-confirm',max_age=3000)
    msg= Message('CONFIRM MAIL',sender=sender1,recipients=mail)
    link = url_for('confirm_email',token=token,_external=true)
    msg.body = 'THANK YOU fOR JOINING US. YOUR CONFIRMATION LINK {}'.format(link)
    return jsonify({"CONFIRmATION mAIL SENT"})
   except :
      return '<h1>404</h1>'

        ######### SWAGGER ########
'''
@app.route('/static/<path:path>')
def send_static(path):
   return send_from_directory('static',path)

SWAGGER_URL='/swagger'
API_URL='/static/swagger.json'
swaggerui_blueprint=get_swaggerui_blueprint(
                                             SWAGGER_URL,
                                             API_URL,
                                             config={
                                                'app_name':"Get_Book-Rest-API"
                                             }
                                             )
app.register_blueprint(swaggerui_blueprint,url_prefix=SWAGGER_URL)

#app.register_blueprint(request_api.get_blueprint())
'''
        ####### REGISTRATION ########   

######### user ######

@app.route('/register', methods=['GET', 'POST'])
class Register(Resource):
   def signup_user():  
      try:
         data = request.get_json()
         passw=generate_password_hash(data['password'])
         public=str(uuid.uuid4())
         new_user=Users(public_id=public,name=data['name'],password=passw,admin=False,activate=False)
         db.session.add(new_user)  
         db.session.commit() 
         #check_email(data['email_id'])
         email=data['email_id']
         #try:
         token= s.dumps(email,salt='email-confirm')
         #mail = s.loads(token,salt='email-confirm',max_age=3000)

         template=jinja_env.get_template('email.html')

         msg= Message('CONFIRM MAIL',sender=sender1,recipients=[email] )
         link = url_for('confirm_email',public=public,token=token,_external=true)
         msg.body = template.render(token_link=(link))
         msg.html=msg.body
         mail.send(msg)

         return jsonify({"message":"CONFIRmATION_mAIL_SENT"})
         #except :
         #   return make_response('<h1>404</h1>',404)


      except :
         return jsonify({"ERROR"})

@app.route('/confirm_email/<public>/<token>')
class Confirmmail(Resource):
 def confirm_email(token,public):
   try:
      mail = s.loads(token,salt='email-confirm',max_age=3000)
      try:
         user=Users.query.filter_by(public_id=public).first()
         user.activate=True
         db.session.commit()
      except:   
         return jsonify({"USER NOT FOUND TRY LOGIN AGAIN"})
   except:
      return jsonify({"TOKEN EXPIRED"})
   return '<h1> THANK YOU </h1>'  


   ########### book ###########
   
@app.route('/book', methods=['GET', 'POST'])
class Book(Resource):
  def enter_book():  
   try:  
      data = request.get_json()  

      new_book = Books(book_id=str(uuid.uuid4()), book_name=data['name'], in_stock=data['in_stock']) 
      db.session.add(new_book)  
      db.session.commit()    

      return jsonify({'message': 'registered successfully'})
   except :
      return jsonify({'message':'Data incorrect'})

         ########## LOGIN ##########


@app.route('/login', methods=['GET', 'POST'])  
class Login(Resource):
 def login_user(): 
   
   auth = request.authorization   

   if not auth or not auth.username or not auth.password:  
      return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

   user = Users.query.filter_by(name=auth.username).first()

   if not user:
      return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    
         
   if check_password_hash(user.password, auth.password):  
      if not user.activate :
         return jsonify({"message":"Please activate Mail"})
      token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
      return jsonify({'token' : token}) 

   return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

            ############ SEARCH ################

@app.route('/user',methods=['GET','POST'])
class Search(Resource):
 def search_user():
   users=Users.query.all()
   data=request.get_json()


   for user in users:
      if user.public_id == data['public_id']:
         user_data = {}   
         user_data['public_id'] = user.public_id  
         user_data['name'] = user.name 
         #user_data['password'] = user.password
         user_data['admin'] = user.admin 
         return jsonify({'users': user_data})   

   return jsonify({'message':'public_id not found'})

            ############ ALL_USERS #############


@app.route('/users', methods=['GET'])
class All_Users(Resource):
 def get_all_users():  
   
   users = Users.query.all() 

   result = []   

   for user in users:   
       user_data = {}   
       user_data['public_id'] = user.public_id  
       user_data['name'] = user.name 
       #user_data['password'] = user.password
       user_data['admin'] = user.admin 
       user_data['activate']=user.activate
       result.append(user_data)   

   return jsonify({'users': result})
            ########## books ##############
@app.route('/books', methods=['GET'])
class All_Book(Resource):
 @token_required
 def get_all_books(current_user):  
   
   users = Books.query.all() 

   result = []   

   for user in users:   
       user_data = {}   
       user_data['public_id'] = user.book_id  
       user_data['name'] = user.book_name 
       user_data['admin'] = user.in_stock 
       
       result.append(user_data)   

   return jsonify({'books': result})
   
        ########## *[DELETE]* ##########
'''
#@app.route('/user/<user_id>',methods=['DELETE'])
#@token_required
#def delete_user(public_id,current_user):
#   if not current_user.admin :
#      return jsonify({"message":"NOT PRIVILEGED"})
#
#   user = user.query.filter_by(public_id=public_id).first()   
#   if not user: 
#      return jsonify({'message':'public_id not found'})
#   db.session.delete(user)
#   db.session.commit()
#   return jsonify({"message":"UsER DELETED"})
'''
   ####### Book #########

@app.route('/book/<book_id>', methods=['DELETE'])
class Del_Book(Resource):
   @token_required
   def delete_book(current_user, book_id):  
    
    if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

    book = book.query.filter_by(id=book_id, user_id=current_user.id).first()   
    if not book:   
       return jsonify({'message': 'book does not exist'})   

    
    db.session.delete(book)  
    db.session.commit()   

    return jsonify({'message': 'Book sucessfully deleted'})

   ########### User ##############

@app.route('/user/<user_id>',methods=['DELETE'])

class Del_User(Resource):
 @token_required
 def delete_user(current_user,user_id):
   if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

   user=Users.query.filter_by(public_id=user_id,).first()
   if not user:
      return jsonify({'message':'User Missing'})
   
   db.session.delete(user)  
   db.session.commit()   

   return jsonify({'message': 'User sucessfully deleted'})

            ################ ADMIN_Rights ##################

   ######### Make_Admin ################

@app.route('/make_admin',methods=['PUT'])
class Make_ADmin(Resource):
 @token_required
 def ruler(current_user):

   if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

   users=Users.query.all()
   data=request.get_json()
   for user in users:
      if user.public_id == data['public_id']:
       user.admin=True
       db.session.execute(update(Users).where(Users.public_id==user.public_id).values(admin=True))
       db.session.commit()
       return jsonify({'message':'Earlship Granted'})
   
   return jsonify({'message':'User Does not EXIST'})

   ############ Revoke Admin #############

@app.route('/revoke_admin',methods=['PUT'])

class Demote(Resource):
 @token_required
 def demote(current_user):

   if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

   users=Users.query.all()
   data=request.get_json()
   for user in users:
      if user.public_id == data['public_id']:
       db.session.execute(update(Users).where(Users.public_id==user.public_id).values(admin=False))
       db.session.commit()
       return jsonify({'message':'Earlship Revoked'})
   
   return jsonify({'message':'User Does not EXIST'})

   ################ Modify Book ################

@app.route('/book',methods=['PUT'])
class Book_Status(Resource):
 @token_required
 def modify_bookstatus(current_user):
   if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

   books=Books.query.all()
   data=request.get_json()
   try:
      for book in books:
         if book.book_id==data['book_id']:
            db.session.execute(update(Books).where(Books.book_id==book.book_id).values(in_stock=data['in_stock'],book_name=data['name']))
            db.session.commit()
            return jsonify({'message':"modified"})
   except Exception as e:
      
         return e and jsonify({'message':'error'})
   
    ################## PATCH ######################
   
@app.route('/user/patch',methods=['PATCH'])

class Patch(Resource):
 @token_required
 def user_patch(current_user):
   if not current_user.admin :
      return jsonify({"message":"NOT PRIVILEGED"})

   
   try:
      data=request.get_json()   
      user=Users.query.filter_by(public_id=data['public_id']).first()
   
      #users=Users.query.all()
      user.name=data['name']
      user.password=generate_password_hash(data['password'])
      user.admin=data['admin']
      db.session.commit()
      return jsonify({'message':'User Upadated'})
   except:
      return jsonify({'message':'User Does not EXIST'})

      ######################### Landing #################################

@app.route('/')
def welcome():    
    return '<style>p,body,h1{text-align:center;}</style><p><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/92/Open_book_nae_02.svg/375px-Open_book_nae_02.svg.png" width="400" height="300"></p><h1><i><em>YOU CAN GET BOOKS!!!</em></i></h1><body><div><a href="http://127.0.0.1:5000/users">View Users</a><br><br><a href="http://127.0.0.1:5000/books">View Books</a></div></body>'

api.add_resource(Book,'/api/book')
api.add_resource(Register,'/api/register')
api.add_resource(Login,'/api/login')
api.add_resource(Search,'/api/user')
api.add_resource(All_Users,'/api/users')
api.add_resource(All_Book,'/api/books')
api.add_resource(Del_Book,'/api/book/<book_id>')
api.add_resource(Del_User,'/api/User/<user_id>')
api.add_resource(Make_ADmin,'/api/makeadmin')
api.add_resource(Demote,'/api/demote')
api.add_resource(Book_Status,'/api/book_status')
api.add_resource(Patch,'/api/book')


###########################  MAIN  ####################################



if __name__ == '__main__' :
    app.run(debug=True)



###################################### END OF CODE #########################################