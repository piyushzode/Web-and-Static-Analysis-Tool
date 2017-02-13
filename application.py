import os
import pymysql
from pymongo import MongoClient
from flask import Flask,request,render_template,redirect,url_for,send_from_directory,session
import sys
import subprocess
import gridfs
import base64
import pyDes
import mongoDB_config
import re
import hashlib, uuid
import bcrypt


application = Flask(__name__)
application.secret_key = "XXXXXXXXXXX"

# Public DNS Name
HOST = "ec2-35-XXX-XXX-XXX.us-west-2.compute.amazonaws.com"
PORT = os.getenv(6000)

# For encrypting
k = pyDes.des(b"DESCRYPT", pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)


@application.route('/',methods=['GET','POST'])
def hello_world():
        if 'username' in session:       ## If user logged in session, then directly redirect the user to upload page
            username = session['username']
            db = db_connection()
            fs = gridfs.GridFS(db)
            items_list = []
            for item in db.fs.files.find({"username":username}):
                file_name = item['filename']
                file_internal = fs.find_one({"filename": file_name}).read()
                items_display={}
                items_display['username'] = item['username']
                items_display['filename'] = item['filename']
                items_display['file_content'] = file_internal
                items_display['tool'] = item['tool']
                items_display['file_result'] = item['result']
                items_list.append(items_display)

            return render_template('upload_page.html', items=items_list,username=username)

        return render_template('index.html')


@application.route('/login_init',methods=['GET','POST'])
def login_init():
        return render_template('index.html')

#connect to DB
def db_connection():
        db_username = mongoDB_config.db_username
        db_pass = base64.b64decode(mongoDB_config.db_password)
        dbname = mongoDB_config.db_name

        connection_str = "mongodb://"+db_username+":"+db_pass+"@dsXXXXXX.mlab.com:15798/"+dbname
        client = MongoClient(connection_str)
        db = client.mysecureproject
        db.authenticate(db_username,db_pass)
        return db

# If new user registeration
@application.route('/new_user',methods=['POST','GET'])
def new_user():
        return render_template('new_user.html')


@application.route('/logout',methods=['POST','GET'])
def logout():
        session.pop('username', None)
        return render_template('index.html')
    
# New user registeration
@application.route('/new_user_register',methods=['POST','GET'])
def new_user_register():
        db = db_connection()

        username = request.form['username']
        if (re.match(r'[A-Za-z0-9@#$%^&+=]{4,}', request.form['pass'])):
            if (re.match(r'[A-Za-z0-9]{4,}', username)):
                if (re.match(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{3,}', request.form['email'])):
                    
                    passw = request.form['pass']
                    #salt = uuid.uuid4().hex
                    #password = hashlib.sha512(passw + salt).hexdigest()

                    password = bcrypt.hashpw(passw, bcrypt.gensalt())
                    email = request.form['email']
                    
                    item_doc = {
                        'username': username,
                        'password': password,
                        'email': email
                    }

                    res = db.user_details.find(item_doc).count()>0

                    if(res):
                        return '<h1>User Already Exists!</h1><br>Time Taken = <br><br><form action="../"><input type="Submit" value="Back"></form>'
                    else:
                        db.user_details.insert_one(item_doc)	
                        return render_template('index.html')
                else:
                    return '<h1>Invalid Email ID! Please use appropriate Email ID</h1><br><br><br><form action="../"><input type="Submit" value="Back"></form>'
            else:
                return '<h1>Invalid Username! Please use appropriate Username</h1><br><br><br><form action="../"><input type="Submit" value="Back"></form>'        
        else:
            return '<h1>Invalid Password! Please use appropriate password</h1><br><br><br><form action="../"><input type="Submit" value="Back"></form>'
            
        

# Login Functionality check
@application.route('/login',methods=['POST'])
def upload_file():
        username=request.form['username']
        if (re.match(r'[A-Za-z0-9@#$%^&+=]{4,}', request.form['pass'])):
            if (re.match(r'[A-Za-z0-9]{4,}', username)):
                #password=base64.b64encode(request.form['pass'])
                passw = request.form['pass']
                #passwd = bcrypt.hashpw(passw, bcrypt.gensalt( 12 ))
                #print(passwd)
                #salt = uuid.uuid4().hex
                #password = hashlib.sha512(passwd + salt).hexdigest()
                ##code to check the user input whitelisting
                #print(password)
                items_list = []

                db = db_connection()
                #res = db.user_details.find({'password':password,'username':username}).count()>0
                res = db.user_details.find({'username':username}).count()>0
                res1 = db.user_details.find({'username':username})

                fs = gridfs.GridFS(db)

                if (res) :
                    
                    for item in db.user_details.find({'username':username}):
                        passwd = item['password']
                        ## Check the hashed password
                        result = bcrypt.checkpw(passw, passwd)
                        print "Result is:"
                        print(result)

                #if(u_id) :
                        if(result == True):
                            global u_name
                            u_name=username
                            session['username'] = u_name
                            print "Logged in successfully"
                            for item in db.fs.files.find({"username":username}):
                                file_name = item['filename']
                                file_internal = fs.find_one({"filename": file_name}).read()
                                items_display={}
                                items_display['username'] = item['username']
                                items_display['filename'] = item['filename']
                                items_display['file_content'] = file_internal
                                items_display['tool'] = item['tool']
                                items_display['file_result'] = item['result']
                                #k.decrypt(item['result']).decode('UTF-8')
                                items_list.append(items_display)

                            return render_template('upload_page.html', items=items_list,username=username)
                        else:
                            return '<h1>Invalid Password Please check your password!</h1><br><form action="../"><input type="Submit" value="Back"></form>'        
                else:
                    return '<h1>User not found!</h1><br><form action="../"><input type="Submit" value="Back"></form>'
            else:
                return '<h1>Invalid Username! Please use appropriate Username</h1><br><br><br><form action="../"><input type="Submit" value="Back"></form>'        
        else:
            return '<h1>Invalid Password! Please use appropriate password</h1><br><br><br><form action="../"><input type="Submit" value="Back"></form>'


# Upload File Functionality
@application.route('/upload_page_analyze', methods=['POST'])
def upload_page_analyze():
    if 'username' in session:
        db = db_connection()
        file_to_upload = request.files.get('file_upload')
        file_name = file_to_upload.filename
        file_data = file_to_upload.read()
        
        length_file = len(file_data)
        print "Length of file is: "+str(length_file)

        if(length_file > 0):
            if(length_file < 250000):
                fs = gridfs.GridFS(db)
                if (re.match(r'[\w,\s-]+\.[A-Za-z]{1}', file_name)):
                    global u_name
                    username = session['username']
                    
                    Encrypted_file_content = k.encrypt(file_data)

                    tmp = file_name.split(".")
                    tool_used = ""

                    if((tmp[1]).lower() == "py"):
                        running_command = "pylint "+file_name+">analysed_"+file_name
                        #result = subprocess.Popen(running_command, shell=True, stdout=subprocess.PIPE).stdout.read()
                        result = os.system(running_command)
                        tool_used = "PyLint"
                        print "File analyzed"
                    elif( ((tmp[1]).lower() == "c") or ((tmp[1]).lower() == "cpp") ): 
                        running_command = "flawfinder "+file_name+">analysed_"+file_name
                        #result = subprocess.Popen(running_command, shell=True, stdout=subprocess.PIPE).stdout.read()
                        result = os.system(running_command)
                        tool_used = "FlawFinder"
                        print "File analyzed"
                    else:
                        return '<h1>Invalid File type uploaded! Please upload Proper File</h1><br><form action="../"><input type="Submit" value="Back"></form>'
                    #tmp = pic_name.split(".")
                    print "File_type"
                    print str(result)

                    

                    f = open('analysed_'+file_name, 'r')
                    contents = f.read()
                    Encrypted_result_content = k.encrypt(contents)

                    #stored = fs.put(file_data, filename=file_name, username=username, result=Encrypted_result_content, file_content=Encrypted_file_content)
                    stored = fs.put(file_data, filename=file_name, tool=tool_used, username=username, result=contents)

                    ## Removing analysed files
                    new_cmd = "rm -rf analysed_"+file_name
                    os.system(new_cmd)
                    res = os.system('echo $?')

                    if (res == 0):
                        print "File deleted successfully"
                    else:
                        print "File not deleted"

                    items_list=[]

                    for item in db.fs.files.find({"username":username}):
                        file_name = item['filename']
                        file_internal = fs.find_one({"filename": file_name}).read()
                        items_display={}
                        items_display['username'] = item['username']
                        items_display['filename'] = item['filename']
                        items_display['tool'] = item['tool']
                        items_display['file_content'] = file_internal
                        items_display['file_result'] = item['result'] 
                        #k.decrypt(item['result']).decode('UTF-8')
                        items_list.append(items_display)
                    return render_template('upload_page.html', items=items_list,username=username)
                else:
                    return '<h1>Invalid File Name! Please upload Proper File</h1><br><form action="../"><input type="Submit" value="Back"></form>'
            else:
                return '<h1>File too big!! Please upload a file less than 2 MB</h1><br><form action="../"><input type="Submit" value="Back"></form>'
        else:
            return '<h1>File is blank!! Please upload a proper file</h1><br><form action="../"><input type="Submit" value="Back"></form>'

    else:
        return render_template('index.html')

if __name__ == '__main__':
        application.run(host=HOST,port=PORT)