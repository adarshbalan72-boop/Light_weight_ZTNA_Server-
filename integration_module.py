import requests
from netmiko import ConnectHandler
from ldap3 import Server,Connection,Tls
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import xml.etree.ElementTree as ET


config_file=r"config_srv.xml"
def confi_file_call():
    tree=ET.parse(config_file)
    root=tree.getroot()
    return tree , root

def FortiGate_Allow(device_ip,device_port,device_toke,ip,group):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #api_key="5ghpbxbgwQrj173Hd68bggdf0kkq0h"
    header={"Authorization":f"Bearer {device_toke}"}
    payload={"name":ip,"subnet":f"{ip} 255.255.255.255"}    
    ip_send=requests.post(f"https://{device_ip}:{device_port}/api/v2/cmdb/firewall/address",headers=header,json=payload,verify=False,timeout=5)
    group_payload=payload = {"name": ip}
    group_send=requests.post(f"https://{device_ip}:{device_port}/api/v2/cmdb/firewall/addrgrp/{group}/member",headers=header,json=group_payload,verify=False,timeout=5)
    return group_send.json(),group_send.status_code
def FortiGate_Delete(device_ip,device_port,device_toke,ip,group):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    api_key="5ghpbxbgwQrj173Hd68bggdf0kkq0h"
    header={"Authorization":f"Bearer {device_toke}"}
    group_send=requests.delete(f"https://{device_ip}:{device_port}/api/v2/cmdb/firewall/addrgrp/{group}/member/{ip}",headers=header,verify=False,timeout=5)
    ip_send=requests.delete(f"https://{device_ip}:{device_port}/api/v2/cmdb/firewall/address/{ip}",headers=header,verify=False,timeout=5)
    return ip_send.json(),ip_send.status_code
def ArubaCX_OS_SSH_Allow (device_ip,device_username,device_password,ip,group):
    device_type="aruba_aoscx"
    #device_ip="172.20.10.7"
    #username="admin"
    #password="Admin@123"
    device_cli = ConnectHandler(device_type="aruba_aoscx",
    host=device_ip,
    username=device_username,
    password=device_password,)
    result=device_cli.send_command(f"show object-group ip address {group} | include {ip}")
    if ip not in result:
        command_result=device_cli.send_config_set([f"object-group ip address {group}",
                                f"{ip}/32"])
    else:
        pass
    device_cli.save_config()
    device_cli.disconnect()
    return {"status":"sucess"},200
    # https://airheads.hpe.com/discussion/aruba-python-automation
    # https://pynet.twb-tech.com/blog/netmiko-python-library.html


def ArubaCX_OS_SSH_Delete(device_ip,device_username,device_password,ip,group):
    tree,root=confi_file_call()
    device_cli = ConnectHandler(device_type="aruba_aoscx",
    host=device_ip,
    username=device_username,
    password=device_password,)
    result=device_cli.send_command(f"show object-group ip address {group} | include {ip}")
    if ip in result:
        id = result.split(ip)[0].strip()
        device_cli.send_config_set([f"object-group ip address {group}",
                                f"no {id}"])
        
        device_cli.save_config()
        

    
    device_cli.disconnect()
    return {"status":"sucess"},200

def ldap_username_search(username):
    tree,root=confi_file_call()
    device_ip=""
    device_username=""
    device_password=""
    intergration_list=root.find("integration")
    for network_inter in intergration_list.findall("user_database"):
        device_type=network_inter.findtext("database_type")
        if device_type == "LDAP":
            device_ip=network_inter.findtext("ip")
            device_username=network_inter.findtext("username")
            device_password=network_inter.findtext("password")
    server=Server(device_ip,port=636,use_ssl=True)
    conn = Connection(server,user=device_username,password=device_password,raise_exceptions=True,auto_bind=True)
    #if conn.bind():
    #    print("connected")
    Groups=["Normal Users","Full access"]
    conn.search(search_base="DC=adarsh-project,DC=lab",search_filter=f"(sAMAccountName={username})",attributes=["memberOf"])
    
    for result in conn.entries:
        for group in result.memberOf:
            group=group.split("CN=")[1].split(",")[0]
            if group in Groups:
                #print(group)
                return group

def device_allow(ip,group):
    tree,root=confi_file_call()
    permitted_device_name=""
    for permision in root.findall(f"./group_list/group_name[name='{group}']/permission"):
        permitted_device_name=permision.text
        for network_inter in root.findall(f"./integration/network_device[device_name='{permitted_device_name}']"):
            device_type=network_inter.findtext("device_type")
            if device_type == "FGT":
                print("intergration with fortigate")
                device_ip=network_inter.findtext("ip")
                device_port=network_inter.findtext("port")
                device_toke=network_inter.findtext("token")
                result,api_status_code= FortiGate_Allow(device_ip,device_port,device_toke,ip,group)
            if device_type == "aruba_aoscx":
                print("intergration with Aruba")
                device_ip=network_inter.findtext("ip")
                device_username=network_inter.findtext("username")
                device_password=network_inter.findtext("password")
                if group=="Full access":
                    group="Full_access"
                result,api_status_code==ArubaCX_OS_SSH_Allow(device_ip,device_username,device_password,ip,group)
                #result={"status":"success"}
                #api_status_code="200"
    return result,api_status_code
def device_delete(ip,group):
    print(ip,group)
    tree,root=confi_file_call()

    permitted_device_name=""
    for permision in root.findall(f"./group_list/group_name[name='{group}']/permission"):
        permitted_device_name=permision.text
        for network_inter in root.findall(f"./integration/network_device[device_name='{permitted_device_name}']"):
            device_type=network_inter.findtext("device_type")
            if device_type == "FGT":
                device_ip=network_inter.findtext("ip")
                device_port=network_inter.findtext("port")
                device_toke=network_inter.findtext("token")
                #print(device_ip,device_port,device_toke,ip,group)
                result,api_status_code = FortiGate_Delete(device_ip,device_port,device_toke,ip,group)
            if device_type == "aruba_aoscx":
                if group == "Full access":
                    group="Full_access"
                device_ip=network_inter.findtext("ip")
                device_username=network_inter.findtext("username")
                device_password=network_inter.findtext("password")
                result,api_status_code= ArubaCX_OS_SSH_Delete(device_ip,device_username,device_password,ip,group)
                #result={"status":"success"}
                #api_status_code="200"
    return result,api_status_code
                