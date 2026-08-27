from flask import Flask, jsonify, request
import os
import xml.etree.ElementTree as ET
import uuid
from datetime import datetime
import json
import requests
import urllib3
import integration_module
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#test
folder="userdata"
config_file="config_srv.xml"
def get_xml_file():
    tree=ET.parse(config_file)
    root=tree.getroot()
    return tree,root

os.makedirs(folder , exist_ok=True)
log_file_location="log/log.txt"

if not os.path.exists(log_file_location):
    with open(log_file_location,"w") as file:
        file.write("")

def log_generation(ip,uid,message):

    log_file=open(log_file_location,"a")
    current=datetime.now()
    log_file.write(f"{current} {ip} {uid} {message} \n")



def posturing(user_data):
    tree,root=get_xml_file()
    print("posturing started")
    application_details=user_data["application_details"]
    os_details=user_data["os_version_details"]
    antivirus_details=user_data["antivirus_details"]
    network_details=user_data["network_details"]
    user_details=user_data["user_details"]
    user_domain=user_data["domain_details"]
    grouplist=["Normal Users","Full access"]
    users_list=[]
    OS_allowed=[]
    black_list=[]
    allowed_domain=[]
    access_group=""
    
    action="approved"
    reason=[]

    for os_name in root.findall("./allowed_os_list/allowed_os"):
        OS_allowed.append({"OS_Build":os_name.findtext("os"),"version":os_name.findtext("version")})
    for local_user_list in root.findall(".local_user_list/local_user"):
        users_list.append({"username":local_user_list .findtext("username"),"group":local_user_list .findtext("group")})
    for ldap_user_list in root.findall("./external_users/ldap_users"):
        users_list.append({"username":ldap_user_list.findtext("username"),"group":ldap_user_list.findtext("group")})
    for app_list in root.findall("./black_list_app/app"):
        black_list.append(app_list.text)
    for domain_list in root.findall("./allowed_domain_list/allowed_domain"):
        allowed_domain.append(domain_list.findtext("domain"))
    

    
    username=""
    for line in user_details:
        if "User Name:" in line:
            username=line.split(":")[1].strip()
            print(username)

    UserName_status=False
    for user_line in users_list:
        local_user=user_line["username"]
        group=user_line["group"]
        ldap_group=integration_module.ldap_username_search(username)
        print(f"intergration result {ldap_group}")
        if ldap_group in grouplist:
            access_group=ldap_group
            print(f"matched with {ldap_group}")
            print("ldap user match")
            UserName_status=True
            break
        elif username == local_user:
            print(f"username matched {username}")
            UserName_status=True
            access_group=group
            print(access_group)
            break
        else:
            pass
            
    if not UserName_status:
        action="deny"
        reason.append("User not match with internal or external, ")
        print("user not founded")

    #print(action)
    
    os_name=""
    os_version=""
    OS_match=False
    #print(OS_allowed)
    for line in os_details:
        if "OS Name:" in line:
            os_name=line.split("OS Name:")[1].strip()
            #print(os_name)
    if "OS Version:" in line:
        os_version=line.split("OS Version:")[1].strip()
        print(os_version)
    for os_allowed_list in OS_allowed:
        os_build=os_allowed_list["OS_Build"]
        os_version_allowed=os_allowed_list["version"]
        if os_name == os_build:
            OS_match=True
            print("OS match")
            print(os_build)
            if os_version >= os_version_allowed:
                print("version accepted")
                break
            else:
                action="deny"
                print("version rejected")
                reason.append("os version not accepted, ")
    if not OS_match:
        action="deny"
        print("OS reject")
        reason.append("os not accepted, ")
        
    #print(action)
    for line in antivirus_details:
        av_status_code=""
        if "AV State" in line:
            av_status_code=int(line.split("AV State:")[1].strip())
            if av_status_code == 397568:
                print("AV is okay")
            else:
                action="deny"
                print(f"AV failed - AV status code:{av_status_code}")
                reason.append("AV status not acceptable, ")
    domain_name=""   
    domain_match=False

    for line in user_domain:
        print("domain check")
        if "Domain Name" in line:
            domain_name=line.split("Domain Name:")[1].strip()
            break
    for allowed in allowed_domain:
        if domain_name.lower() == allowed.lower():
            domain_match=True
            print(f"{line} matched")
            break
    if not domain_match:
        print("domain not matched")
        reason.append("Domain not allowed, ")
        action="deny"            

    print(action)


    if any (app.lower() in line.lower() for app in black_list for line in application_details):
        action="deny"
        print("Black listed application detected")
        reason.append("Black listed application detected, ")
    result={"status": action,
            "reason":reason,
            "group":access_group}
    return(result)


app = Flask (__name__)




app.config["folder"]=folder

@app.route('/userdata', methods=['POST'])

def userdata():
    tree,root=get_xml_file()
    full_data=request.get_json()
    local_ip=request.remote_addr
    uid=full_data["UID"]
    timestamp=datetime.now().isoformat()
    log_generation(local_ip,uid,"userdata recived")
    last_login_user_split=full_data["user_details"]
    print(last_login_user_split)
    last_seen_user=None
    for line in last_login_user_split:
        if "User Name:" in line:
            print(line)
            last_username=line.split(":")[1].strip()
            break

    for endpoint in root.find("reg_endpoint_details").findall("endpoint"):
        exist_uid=endpoint.find("UID").text
        #print(exist_uid)
        if exist_uid==uid:
                last_seen_user=last_scene_ip=endpoint.find("username")
                last_seen_user.text=last_username
                last_group=endpoint.find("last_group")
                last_scene_ip=endpoint.find("last_ip")
                if last_scene_ip is None:
                    last_scene_ip=ET.SubElement(endpoint,"last_ip")
                last_scene_ip.text=local_ip
                last_scene=endpoint.find("last_update")
                if last_scene is None:
                    last_scene=ET.SubElement(endpoint,"last_update")
                last_scene.text=timestamp
                device_status=endpoint.find("device_status")
                if device_status is None:
                    device_status=ET.SubElement(endpoint,"device_status") 
                if last_group is None:
                    last_group=ET.SubElement(endpoint,"last_group")
                result=posturing(full_data)
                posturing_status=result["status"]
                #print(posturing_status)
                group=result["group"]
                #print(group)
                reason=result["reason"]
                last_group.text=group
                log_generation(local_ip,uid,result)
                if posturing_status== "approved":
                    device_status.text="online"
                    try:
                        print(f"group name {group}")
                        int_result,status_code=integration_module.device_allow(local_ip,group)
                        #print(f"result {int_result}statu{status_code}")
                        if int_result["status"] == "error":
                            print("Firewall reject the configuration")
                        elif status_code == "200":
                            print(f"API error code {status_code}")
                    except Exception as error:
                        print("API failed couldnt allow the access")
                else:
                    print("Posturing failed")
                ET.indent(tree, space="    ", level=0)
                tree.write(config_file,encoding="utf-8",xml_declaration=True)
                filepath = os.path.join(app.config['folder'],f"{uid}.json")
                with open(filepath,"w") as file:
                    json.dump(full_data,file,indent=4)
                return jsonify(result)
                break
        else:
            pass
    #log_generation(local_ip,uid,"uid not exist in the configuration file")
    return jsonify({"message":"user is not registred"})
@app.route('/reg', methods=['POST'])
def reg():
    tree,root=get_xml_file()
    reg_data=request.get_json()
    log_generation(request.remote_addr,"new request no UID","userdata recived")
    for line in reg_data["os_version_details"]:
        if line.startswith("OS Name:"):
            os_name=line.split(":",1)[1].strip()
    for line in reg_data["user_details"]:
        if line.startswith("System Name:"):
            system_name=line.split(":",1)[1].strip()  
        if line.startswith("User Name:"):
            user_name=line.split(":",1)[1].strip()
    for line in reg_data["domain_details"]:
        if line.startswith("Domain Name"):
            domain_name=line.split(":",1)[1].strip()
    gen_uid=uuid.uuid4()
    reg_status="pending"
    reg_section=root.find("reg_endpoint_details")
    endpoint=ET.SubElement(reg_section,"endpoint")
    user=ET.SubElement(endpoint,"username")
    user.text=user_name
    system=ET.SubElement(endpoint,"system")
    system.text=system_name
    user=ET.SubElement(endpoint,"domain")
    user.text=domain_name
    os=ET.SubElement(endpoint,"OS")
    os.text=os_name
    uid=ET.SubElement(endpoint,"UID")
    uid.text=str(gen_uid)
    print(gen_uid)
    status=ET.SubElement(endpoint,"status")
    status.text=reg_status
    ET.indent(tree, space="    ", level=0)
    tree.write(config_file,encoding="utf-8",xml_declaration=True)
    log_generation(request.remote_addr,f"assign uid {gen_uid}","request added to the config file")
    return jsonify({"UID":str(gen_uid),"status":"pending"})
@app.route('/reg_pending', methods=['POST'])
def reg_pending():
    tree,root=get_xml_file()
    reg_pend_data=request.get_json()
    recv_uid=str(reg_pend_data["UID"])
    update_status=""
    for endpoint in root.find("reg_endpoint_details").findall("endpoint"):
        exist_uid=endpoint.find("UID").text
        if exist_uid==recv_uid:
            update_status=endpoint.find("status").text
            print(update_status)
    log_generation(request.remote_addr,recv_uid,f"user request for status update and current status {update_status}")
    return jsonify({"UID":str(recv_uid),"status":update_status})


@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    tree,root=get_xml_file()
    config_file="config_srv.xml"
    tree=ET.parse(config_file)
    root=tree.getroot()
    heartbeat=request.get_json()
    recv_uid=str(heartbeat["UID"])
    recv_user_details=heartbeat["user_details"]
    for line in recv_user_details:
        if "User Name:" in line:
            recv_user=line.split(":")[1].strip()
            break
    timestamp=datetime.now().isoformat()
    log_generation(request.remote_addr,recv_uid,"heart beat received")

    for endpoint in root.find("reg_endpoint_details").findall("endpoint"):
        exist_uid=endpoint.find("UID").text
        exist_user=endpoint.find("username").text
        exist_group=endpoint.find("last_group")
        existing_IP=endpoint.find("last_ip")
        current_device_status=endpoint.find("device_status").text
        #print(current_device_status)
        if exist_uid==recv_uid:
            if current_device_status == "online":
                    if exist_user==recv_user:
                        last_scene=endpoint.find("last_update")
                        last_scene.text=timestamp
                        ET.indent(tree, space="    ", level=0)
                        tree.write(config_file,encoding="utf-8",xml_declaration=True)
                        log_generation(request.remote_addr,recv_uid,"heart beat updated")
                        return jsonify({"UID":str(recv_uid),"status":current_device_status})
                    else:
                        if exist_group != None:
                            integration_module.device_delete(existing_IP,exist_group)
                            print("username are differnt")
                            log_generation(request.remote_addr,recv_uid,"heart beat rejected, last seen Username is mismatched requested to reset")
                            return jsonify({"UID":str(recv_uid),"status":"reset the connection"})
                        else:
                            print("group is none")

            else:
                log_generation(request.remote_addr,recv_uid,"heart beat rejected since the device is not online requested to reset")
                return jsonify({"UID":str(recv_uid),"status":"reset the connection"})
    

if __name__ =='__main__':
    app.run(host="0.0.0.0",
    port=5000,
    debug=True)




#https://www.twilio.com/en-us/blog/create-api-with-python
#https://github.com/RNViththagan/Samba-AD-DC-Setup