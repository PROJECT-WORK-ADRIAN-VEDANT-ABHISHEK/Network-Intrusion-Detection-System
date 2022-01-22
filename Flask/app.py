from flask import Flask, render_template, redirect, url_for, request
import psutil
import pyshark
import pandas as pd
import pickle
import socket
from getmac import get_mac_address as gma

app = Flask(__name__)

@app.route('/',methods=["POST","GET"])
def interface_option():
    val1=" "
    interface_list=[]
    addrs = psutil.net_if_addrs()
    for x in addrs.keys():
        interface_list.append(x)
    
    if request.method=="GET":
        return render_template("index.html", interface_list=interface_list)
    else:
        selec =request.form.get('interfaces')
        capture = pyshark.LiveCapture(interface=selec,output_file='packetsaved.pcap')
        capture.sniff(timeout=2)
        data=[]
        print("This is it.")
        print(capture)
        return(str(capture))
        #print(str(selec))
        #return str(selec)

if __name__== "__main__":
    app.run(debug=True)

