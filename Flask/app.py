from flask import Flask, render_template, redirect, url_for, request, jsonify, session, redirect
from functools import wraps
import psutil
import numpy as np
import pyshark
import pandas as pd
import pickle
import socket
from getmac import get_mac_address as gma
#from user.models import User
import pymongo
import uuid
from passlib.hash import pbkdf2_sha256
#from user.models import User


app = Flask(__name__)
app.secret_key= b'\r\xb2XX\x1d\xd3\x0b\xe2\x9b\xe9\x05\xc8ln\xa1$'

#database
client = pymongo.MongoClient('127.0.0.1', 27017)
db = client.user_login_system

#decorators
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap

class User:

    def start_session(self, user):
        del user['password']
        session['logged_in'] = True
        session['user']  = user
        return jsonify(user), 200

    def signup(self):
        #print(request.form)

        #Create user object
        user = {
            "_id":uuid.uuid4().hex,
            "name": request.form.get('name'),
            "email":request.form.get('email'),
            "password":request.form.get('password'),
            "history":""
        }

        # Encrypt the password
        user['password'] = pbkdf2_sha256.encrypt(user['password'])

        #check for existing email
        if db.users.find_one({"email": user['email']}):
            return jsonify({"error": "Email address already in use"}),400

        if db.users.insert_one(user):
           return self.start_session(user) 

        return jsonify({"error": "Signup failed"}), 400

    def signout(self):
        session.clear()
        return redirect('/')

    def login(self):
        user = db.users.find_one({
            "email": request.form.get('email')
            })
        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.start_session(user)
        return jsonify({"error": "Invalid login credentials"}), 401

@app.route('/user/signup', methods=['POST'])
def signup():
    return User().signup()

@app.route('/user/signout')
def signout():
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    return User().login()

@app.route('/history/')
def history():
    return render_template('history.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/')
def index():
    return render_template('index.html')

#@app.route('/user/signup', methods=['POST'])
#def signup():
#    return User().signup()

@app.route('/dashboard/',methods=["POST","GET"])
@login_required
def interface_option():
    val1=" "
    interface_list=[]
    addrs = psutil.net_if_addrs()
    for x in addrs.keys():
        interface_list.append(x)
    
    if request.method=="GET":
        return render_template("dashboard.html", interface_list=interface_list)
    else:
        selec =request.form.get('interfaces')
        capture = pyshark.LiveCapture(interface=selec)
        capture.sniff(timeout=6)
        print(capture)
        data=[]
        penalty = 0
        if len(capture)==0:
            return "No Packet Found"
        else:
            for x in range(len(capture)):
                list_var = x - penalty
                print("In")
                # Appending Protocol
                try:
                    val=capture[x].ip.proto
                    if val=='6':
                        data.append(list())
                        data[list_var].append(1)
                    elif val=='17':
                        data.append(list())
                        data[list_var].append(2)
                    else:
                        penalty = penalty + 1
                        continue
                except:
                    penalty = penalty + 1
                    continue

                # Appending land 
                if val=='6':    
                    if capture[x].eth.dst==capture[x].eth.src and capture[x].tcp.srcport==capture[x].tcp.dstport:
                        data[list_var].append(0)
                    else:
                        data[list_var].append(1)
                elif val=='17':
                    if capture[x].eth.dst==capture[x].eth.src and capture[x].udp.srcport==capture[x].udp.dstport:
                        data[list_var].append(0)
                    else:
                        data[list_var].append(1)


                # Appending urgent
                # I have a doubt here in the definition it is mentioned that in the same connection.
                z=0
                for y in range(len(capture)):
                    if(capture[x].ip.proto=='6'):
                        # Adding exception because eventhough it is passing the if condition, it is throwing the error that it can't find tcp.flags_urg parameter.
                        try:
                            if capture[x].eth.dst==capture[y].eth.dst and capture[x].eth.src==capture[y].eth.src and (capture[y].tcp.flags_urg==1):
                                z=z+1
                        except:
                            continue
                data[list_var].append(z)

                # Appending count
                z=0
                for y in range(len(capture)):
                    if capture[x].eth.dst==capture[y].eth.dst:
                        z=z+1
                data[list_var].append(z)

                # Appending srv_count
                z=0
                for y in range(len(capture)):
                    if val=='6': 
                        try:      
                            if capture[x].tcp.dstport==capture[y].tcp.dstport:
                                z=z+1
                        except:
                            continue
                    elif val=='17':
                        try:
                            if capture[x].udp.dstport==capture[y].udp.dstport:
                                z=z+1
                        except:
                            continue        
                data[list_var].append(z)

                # Appending dst_host_count
                z=0
                for y in range(len(capture)):
                    try:    
                        if capture[x].ip.dst_host==capture[y].ip.dst_host:
                            z=z+1
                    except:
                        continue
                data[list_var].append(z)

                # Appending host_srv_count    IT IS THE SAME CODE AS THE SRV_COUNT BECAUSE I DON'T UNDERSTAND THE DIFF BETWEEN THEM
                z=0
                for y in range(len(capture)):
                    if val=='6':
                        try:    
                            if capture[x].tcp.dstport==capture[y].tcp.dstport:
                                z=z+1
                        except:
                            continue
                    elif val=='17':
                        try:
                            if capture[x].udp.dstport==capture[y].udp.dstport:
                                z=z+1  
                        except:
                            continue      
                data[list_var].append(z)

                # Append host mac

                data[list_var].append(capture[x].ip.src)

                # Append dest mac

                data[list_var].append(capture[x].ip.dst)
            
            # Converting to datafram
            
            df = pd.DataFrame(data)

            # df.to_csv('live.csv', index=False, header=False)    This was for csv
            #print(df)
            clf= pickle.load(open('finalized_model.sav', 'rb'))
            x=df.iloc[:,:-2].values
            result = clf.predict(x)
            nor=[]
            ano=[]
            nor=[1 for x in result if x==1]
            ano=[1 for x in result if x==0]

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            textnote=[]

            num=1
        
            textnote.append(" MAC Address of this device is :  {} ".format(gma()))
            textnote.append(" IP Address of this device is :  {} ".format(s.getsockname()[0]))
            s.close()

            textnote.append("User :" + str(session['user']['_id']))
            textnote.append(" Packets found are {} ".format(len(capture)))
            textnote.append(" Anomaly found are {} ".format(sum(ano)))
            
            found_anomanly_src=[]
            for element in result:
                if element==0 and data[num-1][8] not in found_anomanly_src:

                    found_anomanly_src.append(data[num-1][8])

                    #textnote.append("Packet:- "+ str(num) + " Predicted "+ str(element) + "\n")

                    textnote.append("protocol -" +str(data[num-1][0]))
                    textnote.append("land -" +str(data[num-1][1]))
                    textnote.append("urgent -" +str(data[num-1][2]))
                    textnote.append("count -" +str(data[num-1][3]))
                    textnote.append("srv_count -" +str(data[num-1][4]))
                    textnote.append("dst_host_count -" +str(data[num-1][5]))
                    textnote.append("Dst_host_srv_count -" +str(data[num-1][6]))
                    textnote.append("Dst IP Address -" +str(data[num-1][7]))
                    textnote.append("SRC IP Address -" +str(data[num-1][8]))
                    textnote.append("    ")
                num=num+1

            #inserting records into the User's Database. Need to work on it.... db.users.updateOne is not working.
            db.users.update_one(
                        {
                            "_id": session['user']['_id']
                        },
                        {
                            "$push": {
                                "history": textnote
                            },
                        })
            hist = []

            hist = db.users.find({
                "_id": session['user']['_id']
                },
                {
                    "history":1
                }
                )
            return hist

              
if __name__== "__main__":
    app.run(debug=True)

