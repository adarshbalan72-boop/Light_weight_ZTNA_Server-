
import os
import xml.etree.ElementTree as ET
import uuid
from datetime import datetime
import json

config_file=r"c:/Python/config_srv.xml"
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

sever_status="active"

while "active":
    commad=input("ZTNA SERVER:")
    
    if commad == "help":
        print("""show
            config
            report""")
    elif commad.lower() in ["show ?" , "show -help"]:
        print(""" current-rule\n active-device\n all-device\n pending-device\n show all-users""")
    elif commad.lower() in ["config ?" , "config -help"]:
        print(""" add\n approve\n reject\n intergration""")
    elif commad.lower() in ["config add -help","config add ?"]:
        print(""" os\n local-user\n blacklist-app\n""")
    elif commad.lower() in ["config approve -help" , "config approve ?"]:
        print("device UID")
    elif commad.lower() in ["config reject -help" , "config reject"]:
        print("device UID")
    elif commad.lower() in ["config intergration -help" , "config intergration ?"]:
        print(""" FortiGate\n PaloAlto\n Cisco-cat\n Cisco-Nexus\n Aruba-CXOS\n LDAP\n Radius""")
    elif commad.lower() == "config add os":
        print("enter the input in below format:\n Microsoft Windows 10 Pro\n and add the os version")
        tree,root=confi_file_call()
        current_os_list=root.find("allowed_os_list")
        new_os=input("config>OS:")
        dublicate_status=dublicate_checker(new_os,"allowed_os_list/allowed_os/os")
        if dublicate_status == "dublicate found":
            print(f"The{new_os} has been founded in the existing configuration")
            continue
        else:
            print("Please add the OS version")
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
    elif commad.lower() == "config add local-user":
        print("enter username and group one after other")
        tree,root=confi_file_call()
        user_list=root.find("local_user_list")
        print("please enter the username")
        new_user=input("config>local-user>username:")
        dublicate_status=dublicate_checker(new_user,"local_user_list/local_user/username")
        if dublicate_status == "dublicate found":
            print(f"The{new_user} has been founded in the existing configuration")
            continue
        else:
            print("please enter the Group name")
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
    elif commad.lower() == "config add group":
        print("enter group name")
        tree,root=confi_file_call()
        group_list=root.find("group_list")
        print("please enter the username")
        group_name=input("config>group>name:")
        dublicate_status=dublicate_checker(group_name,"group_list/group_name/name")
        if dublicate_status == "dublicate found":
            print(f"The{group_name} has been founded in the existing configuration")
            continue
        else:
            print("please enter the permited devices")
            add_group=ET.SubElement(group_list,"group_name")
            add_group_name=ET.SubElement(add_group,"name")
            add_group_name.text=group_name
            ET.indent(tree, space="    ", level=0)
            tree.write(config_file,encoding="utf-8",xml_declaration=True)
            tree,root=confi_file_call()
            group_list=root.find("group_list")
            while True:
                print("Once all the devices has been addeded enter 'exit' command")
                group_permission=input(f"config>group>{group_name}>permission:")
                if group_permission=="exit":
                    break
                inter_device_check=dublicate_checker(group_permission,"integration/network_device/device_name")
                if inter_device_check == "dublicate found":
                    for new_group in group_list.findall("group_name"):
                        if new_group.findtext("name")==group_name:
                            add_permission=ET.SubElement(add_group,"permission")
                            add_permission.text=group_permission
                            break
                    ET.indent(tree, space="    ", level=0)
                    tree.write(config_file,encoding="utf-8",xml_declaration=True)
                    tree,root=confi_file_call()
                    group_list=root.find("group_list")
                else:
                    print("The device name is not found in the configuration")
            for current_user in root.findall("group_list/group_name/name"):
                if current_user.text == group_name:
                    print(f"Gorup {group_name} has been added")
    elif commad.lower() == "config add blacklist-app":
        print("please add the black listing application name")
        tree,root=confi_file_call()
        black_list_app=root.find("black_list_app")
        new_app=input("config>blacklist-app:")
        dublicate_status=dublicate_checker(new_app,"black_list_app/app")
        if dublicate_status == "dublicate found":
            print(f"The{new_app} has been founded in the existing configuration")
            continue
        else:
            add_app=ET.SubElement(black_list_app,"app")
            add_app.text=new_app
            ET.indent(tree, space="    ", level=0)
            tree.write(config_file,encoding="utf-8",xml_declaration=True)
            tree,root=confi_file_call()
            for current_list_app in root.findall("black_list_app/app"):
                if current_list_app.text == new_app:
                    print(f"{new_app} has been added to the black list")      
    elif commad.lower() == "config intergration FortiGate":
        print("please enter required details")
        tree,root=confi_file_call()
        integration=root.find("integration")
        network_device=ET.SubElement(integration,"network_device")
        print("please enter the Fortigate IP or Hostname")
        fortigate_IP=input("config>FortiGate>IP:")
        dublicate_status=dublicate_checker(fortigate_IP,"integration/network_device/ip")
        if dublicate_status == "dublicate found":
            print(f"Device {fortigate_IP} device has been founded in the configuration")
            continue
        else:
            print("Please enter management Port number")
            device_port=input(f"config>FortiGate>{fortigate_IP}>Port:")
            print("Please enter API token")
            device_api_token=input(f"config>FortiGate>{fortigate_IP}>API Token:")
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
    elif commad.lower() == "config intergration Aruba-CXOS":
        print("please enter required details")
        tree,root=confi_file_call()
        integration=root.find("integration")
        network_device=ET.SubElement(integration,"network_device")
        print("please enter the Aruba Switch IP or Hostname")
        aruba_ip=input("config>Aruba CX-OS>IP:")
        dublicate_status=dublicate_checker(aruba_ip,"integration/network_device/ip")
        if dublicate_status == "dublicate found":
            print(f"Device {aruba_ip} device has been founded in the configuration")
            continue
        else:
            print("Please enter the SSH username and password")
            aruba_username=input(f"config>aruba CX-OS>{aruba_ip}>username:")
            aruba_password=input(f"config>aruba CX-OS>{aruba_ip}>password:")
            add_device_type=ET.SubElement(network_device,"device_type")
            add_device_type.text="aruba_aoscx"
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
    elif commad.lower() == "config intergration LDAP":
        print("please enter required details")
        tree,root=confi_file_call()
        integration=root.find("integration")
        user_database=ET.SubElement(integration,"user_database")
        print("please enter the LDAP server IP address or Host name")
        new_srv_ip=input("config>LDAP>IP:")
        dublicate_status=dublicate_checker(new_srv_ip,"integration/user_database/ip")
        if dublicate_status == "dublicate found":
            print(f"Device {new_srv_ip} device has been founded in the configuration")
            continue
        else:
            print("Please enter the username and password")
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
    elif commad.lower() == "show all-device":
        tree,root=confi_file_call()
        reg_endpoint_details=root.find("reg_endpoint_details")
        for endpoint in reg_endpoint_details.findall("endpoint"):
            system_name=endpoint.findtext("system")
            UID=endpoint.findtext("UID")
            os=endpoint.findtext("OS")
            last_seen=endpoint.findtext("last_update")
            last_seen_ip=endpoint.findtext("last_ip")
            device_status=endpoint.findtext("device_status")
            reg_status=endpoint.findtext("status")
            last_seen_user=endpoint.findtext("username")
            print(f" ****************************\n {system_name} \n {UID} \n {reg_status}\n {os} \n {last_seen}\n {last_seen_ip}\n {device_status}\n {last_seen_user} \n ****************************\n")
    elif commad.lower() == "show active-device":
        tree,root=confi_file_call()
        reg_endpoint_details=root.find("reg_endpoint_details")
        for endpoint in reg_endpoint_details.findall("endpoint"):
            device_status=endpoint.findtext("device_status")
            if device_status.lower() == "online":
                system_name=endpoint.findtext("system")
                UID=endpoint.findtext("UID")
                os=endpoint.findtext("OS")
                last_seen=endpoint.findtext("last_update")
                last_seen_ip=endpoint.findtext("last_ip")
                reg_status=endpoint.findtext("status")
                last_seen_user=endpoint.findtext("username")
                print(f" ****************************\n {system_name} \n {UID} \n {reg_status}\n {os} \n {last_seen}\n {last_seen_ip}\n {device_status}\n {last_seen_user} \n ****************************\n")
    elif commad.lower() == "show pending-device":
        tree,root=confi_file_call()
        reg_endpoint_details=root.find("reg_endpoint_details")
        for endpoint in reg_endpoint_details.findall("endpoint"):
            reg_status=endpoint.findtext("status")
            #print(reg_status)
            if reg_status.lower() == "pending":
                system_name=endpoint.findtext("system")
                UID=endpoint.findtext("UID")
                os=endpoint.findtext("OS")
                last_seen_user=endpoint.findtext("username")
                print(f" ****************************\n {system_name} \n {UID} \n {reg_status}\n {os}\n {last_seen_user} \n ****************************\n")
    elif commad.lower() == "show current-rule":
        tree,root=confi_file_call()
        show_allow_os_list=root.find("allowed_os_list")
        show_bk_app_list=root.find("black_list_app")
        for show_current_os in show_allow_os_list.findall("allowed_os"):
            show_os=show_current_os.findtext("os")
            show_version=show_current_os.findtext("version")
            print(f" ****************************\n {show_os} and its version and above {show_version} ****************************\n")
        for show_current_bk_app in show_bk_app_list.findall("app"):
            print(f" ****************************\n Blocked Application List\n {show_current_bk_app.text}\n ****************************\n")
    elif commad.lower() == "show all-users":
        tree,root=confi_file_call()
        local_db=root.find("local_user_list")
        external_db=root.find("external_users")
        User_list=[]
        for local_user_list in local_db.findall("local_user"):
            username=local_user_list.findtext("username")
            group=local_user_list.findtext("group")
            user_type="local"
            User_list.append({"username":username,"group":group,"type":user_type})
        for external_user_list in external_db.findall("ldap_users"):
            username=external_user_list.findtext("username")
            group=external_user_list.findtext("group")
            user_type="external-ldap"
            User_list.append({
                              "username":username,
                              "group":group,
                              "type":user_type
                              }
            )
        for userlist_print in User_list:
            print(f" ****************************\n {userlist_print['username']} \n {userlist_print['group']}\n {userlist_print['type']}\n ****************************")
    elif commad.lower() == "show intergration":
         tree,root=confi_file_call()
         intergration_module=root.find("integration")
         inter_list=[]
         for network_inte in intergration_module.findall("network_device"):
             inter_device_IP=network_inte.findtext("ip")
             inter_type=network_inte.findtext("device_type")
             inter_list.append({"device_ip":inter_device_IP,"inter_type":inter_type})
         for user_inte in intergration_module.findall("user_database"):
             inter_device_IP=user_inte.findtext("ip")
             inter_type=user_inte.findtext("database_type")
             inter_list.append({"device_ip":inter_device_IP,"inter_type":inter_type})
         for print_inter in inter_list:
             print(f" ****************************\n {print_inter['device_ip']} \n {print_inter['inter_type']}\n ****************************")
    elif commad.lower() in ["report -help", "report ?"]:
        print ("report device-report")
    elif commad.lower() == "report device-report":
        print ("Please enter the device UID")
        user_uid=input("Rport>UID:")
        file_name=open(f"userdata/{user_uid}.json")
        data=json.load(file_name)
        print("User and host Details")
        print("\n".join(data['user_details']))
        print("Operating system Details")
        print("\n".join(data['os_version_details']))
        print("Antivirus Details")
        print("\n".join(data['antivirus_details']))
        print("Application Details")
        print("\n".join(data['application_details']))
  

    else:
        print("unknow Command")

#print(""" current-rule\n active-device\n all-device\n pending-device""")