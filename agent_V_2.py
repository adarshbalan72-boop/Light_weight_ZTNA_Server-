import subprocess
import socket
import time
import json
import requests
import io
import os
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



status="not_connected"
registartion_status="not registered"   
registration_file=("c:/Python/registration.json")
log_file_location="c:/Python/log/agent_log.txt"

if not os.path.exists(log_file_location):
    with open(log_file_location,"w") as file:
        file.write("")

def log_generation(stage,message):
    log_file=open(log_file_location,"a")
    current=datetime.now()
    log_file.write(f"{current} {stage} {message} \n")

if not os.path.exists(registration_file):
    with open(registration_file,"w") as file:
        file.write("")




def application():
    test =subprocess.run(
        [
            "powershell.exe",
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select DisplayName, DisplayVersion, Publisher"
        ],
        capture_output=True,
        text=True
    )
    return test.stdout.splitlines()
def os_version():  #used Gen AI to generate the Powershell command 
    os_details=subprocess.run(
        [
            "powershell.exe",
            "Write-Output \"OS Name: $((Get-ComputerInfo).OsName)\";" 
            "Write-Output \"OS Version: $((Get-ComputerInfo).OsVersion)\";"
        ],
        capture_output=True,
        text=True
    )
    return os_details.stdout.splitlines()
def antivirus(): #used Gen AI to generate the Powershell command 
    antivirus_details=subprocess.run(
        [
            "powershell.exe",
            "-Command",
            "$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct; "
            "Write-Output \"AV Name: $($av.displayName)\";"
            "Write-Output \"AV State: $($av.productState)\";"
        ],
        capture_output=True,
        text=True
    )
    return antivirus_details.stdout.splitlines()

def network():
    network_details=subprocess.run(
        [
            "powershell.exe",
            "ipconfig /all"
        ],
        capture_output=True,
        text=True
    )
    return network_details.stdout.splitlines()


def user():
    user_details =subprocess.run(
        [
            "powershell.exe",
            "-Command",
            'Write-Output "System Name: $env:COMPUTERNAME"; '
            'Write-Output "User Name: $(((Get-CimInstance Win32_ComputerSystem).UserName).Split(\'\\\')[-1])"'
        ],
        capture_output=True,
        text=True
    )
    #print(user_details.stdout)
    return user_details.stdout.splitlines()
def domain():
    domain_details=subprocess.run(
        [
            "powershell.exe",
            "Write-Output \"Domain Name: $((Get-CimInstance Win32_ComputerSystem).Domain)\";"
        ],
        capture_output=True,
        text=True
    )
    return domain_details.stdout.splitlines()
def uid_grab():
    registration_file.seek(0)
    uid_file=json.load(registration_file)
    uid_for_reg=uid_file["UID"]
    return uid_for_reg



def collected_data():
    return { "UID": uid_grab(),
    "application_details":application(),
    "os_version_details":os_version(),
    "antivirus_details":antivirus(),
    "network_details":network(),
    "user_details":user(),
    "domain_details":domain()
    }

def registration_details():
    return {"os_version_details":os_version(),
            "user_details":user(),
            "domain_details":domain()}
def heartbeat_data():
    registration_file=open("c:/Python/registration.json","r")
    reg_data=json.load(registration_file)
    UID=str(reg_data["UID"])
    return {"UID":UID,
            "user_details":user()}
    



#time.sleep(10)
#print(application,os_version,antivirus,network,user)



while registartion_status=="not registered":
    registration_file=open("c:/Python/registration.json","r+")
    reg_data=registration_file.read()
    print(reg_data)
    print("checking registration")
    log_generation("initiated the registration verification","checking registration file")
    if "UID" not in reg_data :
        print("device is not registered")
        log_generation("registration file verifcation", "not found registration file")
        try:    
            reg_message=registration_details()
            print("reg_sending packet")
            send=requests.post("https://127.0.0.1:5000/reg",json=reg_message,verify=False,timeout=5)
            log_generation("sending registration request", "request send from agent ")
            #response=send.json()
            #recev_UID=response["UID"]
            #recev_status=response["status"]
            print(send.text)
            json.dump(send.json(),registration_file,indent=4)
            registration_file.flush()
            if send.status_code == 200:
                log_generation("sending registration request", " server accepeted the reg request")
                reg_srv_status="connected"
                time.sleep(20)
            else:
                print("connection_failed")
                log_generation("sending registration request", " connection failed ")
        except requests.exceptions.ConnectionError:
            log_generation("sending registration request", " connection failed ")
            print("connection_failed")
        except requests.exceptions.Timeout:
            log_generation("sending registration request", " connection failed ")
            print("connection_failed") 
    elif "pending" in reg_data:
            log_generation("registration status pending", " ")
            print("pending")
            pending_data = json.loads(reg_data)
            try:
                print("send reg request")
                send=requests.post("https://127.0.0.1:5000/reg_pending",json=pending_data,verify=False,timeout=5)
                log_generation("registration status pending", "requested for status update")
                if send.status_code == 200:
                    response=send.text
                    print(response)
                    if send.json()["status"]=="registered":
                        log_generation("registration status pending", "status is change to registrated")
                        print("status registered")
                        registration_file.seek(0)
                        registration_file.truncate()
                        json.dump(send.json(),registration_file,indent=4)
                        registration_file.flush()
                    #registration_file.write(response)
                    elif send.json()["status"]=="pending":
                        time.sleep(10)
                else:
                    log_generation("registration status pending", "connection failed")
                    pass
            except requests.exceptions.ConnectionError:
                status="not_connected"
                log_generation("registration status pending", "connection failed")
            except requests.exceptions.Timeout:
                status="not_connected"
                log_generation("registration status pending", "connection failed")
            
            
    elif "registered" in reg_data:
        log_generation("registration status", "device is registrered")
        print("device is registered")
        registartion_status="registered"

    else:
        log_generation("registration status", "unknow")
        print("unknow error")
        print(reg_data)

  
#with open('agent_details.json', 'w') as json_file:
#    json.dump(data,json_file,indent=4)


while registartion_status=="registered":
    #print(uid)
    
    if status=="not_connected":
        data=collected_data()
        print("sending all data")
        try:
            #json_bytes = io.BytesIO(json.dumps(data,indent=4).encode('utf-8'))
            #json_bytes.seek(0)
            #message_file={"file":("final_file.json", json_bytes , "application/json")}
            #print("start_sending")
            send=requests.post("https://127.0.0.1:5000/userdata",json=data,verify=False,timeout=15)
            #print("test")
            log_generation("posturing request", "send full data")
            print("all packet sended")
            print(send.json())
            reply=send.json()["status"]
            message=send.json()["reason"]
            log_generation("posturing request", f"{reply} {message}")
            
            print(reply)
            print(message)
            if reply == "approved":
                status="connected"
            else:
                print("Posturing failed")
            if not send.status_code == 200:
                log_generation("posturing request", "connection failed")
                print("connection failed")
        except requests.exceptions.ConnectionError:
            print("connection_failed")
            log_generation("posturing request", "connection failed")
        except requests.exceptions.Timeout:
            print("connection_failed")
            log_generation("posturing request", "connection failed")
        time.sleep(10)

    if status=="connected":
        
        heartbeat = heartbeat_data()
        print("sending hello message")
        try:
            log_generation("heartbeat", "sending heartbeat request")
            send=requests.post("https://127.0.0.1:5000/heartbeat",json=heartbeat, verify=False,timeout=5)
            print(send.json())
            rev_status=send.json()["status"]
            log_generation("heartbeat", rev_status)
            if send.status_code == 200:
                if rev_status=="online":
                    print("heartbeat accepted sucessfully")
                    time.sleep(60)
                elif rev_status =="reset the connection":
                    print("server requested to reconnect")
                    status="not_connected"
                
            else:
                log_generation("heartbeat", "heartbeat failed")
                status="not_connected"
        except requests.exceptions.ConnectionError:
            status="not_connected"
            log_generation("heartbeat", "connection failed")
        except requests.exceptions.Timeout:
            log_generation("heartbeat", "connection failed")
            status="not_connected"
        

        






