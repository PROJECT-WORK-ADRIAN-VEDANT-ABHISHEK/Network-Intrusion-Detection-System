from flask import Flask, render_template, redirect, url_for, request
import psutil

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
        print(str(selec))
        return str(selec)

if __name__== "__main__":
    app.run(debug=True)

