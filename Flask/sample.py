import psutil

interface_list=[]

addrs = psutil.net_if_addrs()
for x in addrs.keys():
    interface_list.append(x)
