import xml.etree.ElementTree as ET
import requests
import json
import re


config_file=r"c:/Python/config_srv-ai.xml"
def confi_file_call():
    tree=ET.parse(config_file)
    root=tree.getroot()
    return tree , root
def dublicate_checker(input,entry_path):
    tree,root=confi_file_call()
    status=""
    for config_data in root.findall(entry_path):
        if config_data.text == input:
            status="dublicate found"
            break
        else:
            status="not found"
    return status
def help_menu():
    """
    This funtion is for the help , so if user ask such as manual , help, guide or ? give the appropriate guidence 
    show command is use for showing the existing configuration
    config commands use for configuration 
    monitor commands use for monitoring the device
    """
    return 
def config_os_allow_list(new_os: str,new_os_version: str):
        """"this funtion is used to add the allow or whitlisted OS and OS version list to ZTNA sever, user should provide os name and its versio to add """
        tree,root=confi_file_call()
        current_os_list=root.find("allowed_os_list")
        new_os=input("config>OS:")
        dublicate_status=dublicate_checker(new_os,"allowed_os_list/allowed_os/os")
        if dublicate_status == "dublicate found":
            print(f"The{new_os} has been founded in the existing configuration")
        new_os_version=input(f"config>OS{new_os} version:")
        add_allow_os=ET.SubElement(current_os_list,"allowed_os")
        add_os=ET.SubElement(add_allow_os,"os")
        add_os.text=new_os
        add_version=ET.SubElement(add_allow_os,"version")
        add_version.text=new_os_version
        ET.indent(tree, space="    ", level=0)
        tree.write(config_file,encoding="utf-8",xml_declaration=True)
        tree,root=confi_file_call()
        for update_list in root.findall("allowed_os_list/allowed_os/os"):
            if update_list.text == new_os:
                print(f"configuration updated {new_os} added to the list")
def local_user_creation(new_user: str,new_group: str):
        """this funtion is for creating local user , it required username and group for for adding new users in to local user DB"""
        tree,root=confi_file_call()
        user_list=root.find("local_user_list")
        new_user=input("config>local-user>username:")
        dublicate_status=dublicate_checker(new_user,"local_user_list/local_user/username")
        if dublicate_status == "dublicate found":
            print(f"The{new_user} has been founded in the existing configuration")
        new_group=input("config>local-user>group:")
        add_local_user=ET.SubElement(user_list,"local_user")
        add_user=ET.SubElement(add_local_user,"username")
        add_group=ET.SubElement(add_local_user,"group")
        add_user.text=new_user
        add_group.text=new_group
        ET.indent(tree, space="    ", level=0)
        tree.write(config_file,encoding="utf-8",xml_declaration=True)
        tree,root=confi_file_call()
        for current_user in root.findall("local_user_list/local_user/username"):
            if current_user.text == new_user:
                print(f"username {new_user} has been added")
def configuting_blaklist_app(new_app: str):
        """ this funtion is for adding new application in to black listed Aplication on the configuration file or configuring black listed application"""
        tree,root=confi_file_call()
        black_list_app=root.find("black_list_app")
        new_app=input("config>blacklist-app:")
        dublicate_status=dublicate_checker(new_app,"black_list_app/app")
        if dublicate_status == "dublicate found":
            print(f"The{new_app} has been founded in the existing configuration")
        add_app=ET.SubElement(black_list_app,"app")
        add_app.text=new_app
        ET.indent(tree, space="    ", level=0)
        tree.write(config_file,encoding="utf-8",xml_declaration=True)
        tree,root=confi_file_call()
        for current_list_app in root.findall("black_list_app/app"):
            if current_list_app.text == new_app:
                print(f"{new_app} has been added to the black list") 
def config_intergration_Aruba_CXOS(aruba_ip: str,aruba_username: str,aruba_password: str):
        """ this funtion is for collecting and save aruba switch SSH details for the intergration including IP , username and password"""
        tree,root=confi_file_call()
        integration=root.find("integration")
        network_device=ET.SubElement(integration,"network_device")
        aruba_ip=input("config>Aruba CX-OS>IP:")
        dublicate_status=dublicate_checker(aruba_ip,"integration/network_device/ip")
        if dublicate_status == "dublicate found":
            print(f"Device {aruba_ip} device has been founded in the configuration")
        aruba_username=input(f"config>aruba CX-OS>{aruba_ip}>username:")
        aruba_password=input(f"config>aruba CX-OS>{aruba_ip}>password:")
        add_device_type=ET.SubElement(network_device,"aruba_aoscx")
        add_aruba_ip=ET.SubElement(network_device,"ip")
        add_aruba_ip.text=aruba_ip
        add_aruba_username=ET.SubElement(network_device,"username")
        add_aruba_username.text=aruba_username
        add_aruba_password=ET.SubElement(network_device,"password")
        add_aruba_password.text=aruba_password
        ET.indent(tree, space="    ", level=0)
        tree.write(config_file,encoding="utf-8",xml_declaration=True)
        tree,root=confi_file_call()
        for device_list in root.findall("integration/network_device/ip"):
            if device_list.text == aruba_ip:
                print(f"Device {aruba_ip} has been added")
def config_intergration_LDAP(new_srv_ip: str,srv_username: str,srv_password: str):
        """ this funtion is used to collect and save the LDAP related information including IP, username and password"""
        tree,root=confi_file_call()
        integration=root.find("integration")
        user_database=ET.SubElement(integration,"user_database")
        new_srv_ip=input("config>LDAP>IP:")
        dublicate_status=dublicate_checker(new_srv_ip,"integration/user_database/ip")
        if dublicate_status == "dublicate found":
            print(f"Device {new_srv_ip} device has been founded in the configuration")
        srv_username=input(f"config>LDAP>{new_srv_ip}>username:")
        srv_password=input(f"config>LDAP>{new_srv_ip}>password:")
        user_database_type=ET.SubElement(user_database,"database_type")
        user_database_type.text="LDAP"
        add_srv_ip=ET.SubElement(user_database,"ip")
        add_srv_ip.text=new_srv_ip
        add_srv_username=ET.SubElement(user_database,"username")
        add_srv_username.text=srv_username
        add_srv_password=ET.SubElement(user_database,"password")
        add_srv_password.text=srv_password
        ET.indent(tree, space="    ", level=0)
        tree.write(config_file,encoding="utf-8",xml_declaration=True)
        tree,root=confi_file_call()
        for device_list in root.findall("integration/user_database/ip"):
            if device_list.text == new_srv_ip:
                print(f"Device {new_srv_ip} has been added")
def fortigate_config(fortigate_IP: str,device_port: str, device_api_token: str , ):
    """ this funtion is used for collecting and save fortigate API intergration details including IP , admin port and api token"""
    tree,root=confi_file_call()
    integration=root.find("integration")
    network_device=ET.SubElement(integration,"network_device")
    dublicate_status=dublicate_checker(fortigate_IP,"integration/network_device/ip")
    if dublicate_status == "dublicate found":
        print(f"Device {fortigate_IP} device has been founded in the configuration")
      
    add_device_type=ET.SubElement(network_device,"device_type")
    add_device_type.text="FGT"
    add_device_IP=ET.SubElement(network_device,"ip")
    add_device_IP.text=fortigate_IP
    add_device_port=ET.SubElement(network_device,"port")
    add_device_port.text=device_port
    add_api_token=ET.SubElement(network_device,"token")
    add_api_token.text=device_api_token
    ET.indent(tree, space="    ", level=0)
    tree.write(config_file,encoding="utf-8",xml_declaration=True)
    tree,root=confi_file_call()
    for device_list in root.findall("integration/network_device/ip"):
        if device_list.text == fortigate_IP:
            print(f"device {fortigate_IP} has been added")
    return "success"
client = genai.Client(api_key="AQ.Ab8RN6Lw4gZULxgQp-rpWI5NswTReSsfNd0QQdBRIJzAU9pNtQ")

my_tool=[fortigate_config,help_menu,config_intergration_Aruba_CXOS,config_intergration_LDAP,config_os_allow_list,configuting_blaklist_app,local_user_creation]

chat =client.chats.create(
    model="gemini-2.5-flash",
    config=types.GenerateContentConfig(tools=my_tool,temperature=0.0)
)


all_funtion=[
     "config_intergration_Aruba_CXOS":(config_intergration_Aruba_CXOS,[aruba_ip,aruba_username,aruba_password]),
     "config_intergration_LDAP":(config_intergration_LDAP,[new_srv_ip,srv_username,srv_password]),
     "fortigate_config":(fortigate_config,[fortigate_IP,device_port, device_api_token]),
     "local_user_creation":(local_user_creation,[new_user,new_group]),
     "config_os_allow_list":(config_os_allow_list,[new_os,new_os_version]),
     "configuting_blaklist_app":(configuting_blaklist_app,[new_app]),
]

SYSTEM_PROMPT = """You are an AI assistant managing a ZTNA (Zero Trust Network Access) server.
You can either respond with plain text, OR call one of the available functions below.
 
If the user asks for a configuration action, respond ONLY with a JSON object in this exact format:
{"function": "<function_name>", "args": {"<arg1>": "<value1>", ...}}
 
Do NOT wrap it in markdown code blocks. Output raw JSON only when calling a function.
If you need more information from the user to fill in the arguments, ask for it in plain text first.
Otherwise respond in plain text for general questions, help, or status queries.
 
Available functions:
 
config_os_allow_list(os_name, os_version)
  - Adds an OS and version to the ZTNA whitelist.
  - Example: {"function": "config_os_allow_list", "args": {"os_name": "Windows", "os_version": "11"}}
 
local_user_creation(username, group)
  - Creates a local user with a group assignment.
  - Example: {"function": "local_user_creation", "args": {"username": "jdoe", "group": "admins"}}
 
config_blacklist_app(app_name)
  - Adds an application to the blacklist.
  - Example: {"function": "config_blacklist_app", "args": {"app_name": "BitTorrent"}}
 
config_aruba_cxos(ip, username, password)
  - Integrates an Aruba CX-OS switch via SSH.
  - Example: {"function": "config_aruba_cxos", "args": {"ip": "10.0.0.1", "username": "admin", "password": "secret"}}
 
config_ldap(ip, username, password)
  - Configures an LDAP server integration.
  - Example: {"function": "config_ldap", "args": {"ip": "192.168.1.10", "username": "ldapuser", "password": "secret"}}
 
fortigate_config(ip, port, api_token)
  - Adds a FortiGate firewall via REST API.
  - Example: {"function": "fortigate_config", "args": {"ip": "10.1.1.1", "port": "8443", "api_token": "abc123xyz"}}
"""
## generated by GeN AI for the better understanding , i have provide the my administartor module script, my requirements such as the action and response , then my updated script which i used for GeminiChatAI.


def chat_bot(message):
     Payload={"model":"llama3.2",
              "message":message,
              "stream":False,
              "options":{"temperature":0.0}}
     try:
          req=requests.post("http://localhost:11434/api/chat",json=Payload,timeout=60)
          req.raise_for_status()
          return req.json()["message"]["content"].strip()
     except requests.exceptions.ConnectionError:
          return "connection Error"
     except Exception as eror:
          return f"{eror}"
def json_strip(text):
          

server_status="active"