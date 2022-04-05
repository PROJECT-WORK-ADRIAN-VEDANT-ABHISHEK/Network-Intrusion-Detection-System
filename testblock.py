import subprocess, ctypes, os, sys
from subprocess import Popen, DEVNULL

def chkAdmin():
    """ Force to start application with admin rights """
    try:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        isAdmin = False
    if not isAdmin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

def addRule(rule_name, file_path):
    """ Add rule to Windows Firewall """
    #subprocess.call("netsh advfirewall firewall add rule name="+ rule_name +"profile=All dir=in action=block enable=yes program=any scope={} ".format(file_path), shell=True, stdout=DEVNULL, stderr=DEVNULL)
    subprocess.run(
        [
            'netsh', 'advfirewall', 'firewall',
            'add', 'rule', f'name={rule_name}','profile=any','dir=in','action=block','program=any',f'scope={file_path}',
            'enable=yes',
        ],
        check=True,
        stdout=DEVNULL,
        stderr=DEVNULL
    )
    print("Rule", rule_name, "for", file_path, "added")

def modifyRule(rule_name, state):
    """ Enable/Disable specific rule, 0 = Disable / 1 = Enable """
    if state:
        subprocess.call("netsh advfirewall firewall set rule name="+ rule_name +" new enable=yes", shell=True, stdout=DEVNULL, stderr=DEVNULL)
        print("Rule", rule_name, "Enabled")
    else:
        subprocess.call("netsh advfirewall firewall set rule name="+ rule_name +" new enable=no", shell=True, stdout=DEVNULL, stderr=DEVNULL)
        print("Rule", rule_name, "Disabled")

chkAdmin()
addRule("AAAAAAAAAAAAAAAAAAAAAAAAAA", "172.217.166.174")
#modifyRule("RULE_NAME", 1)