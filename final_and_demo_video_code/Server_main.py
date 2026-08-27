import json
import requests
import time
import xml.etree.ElementTree as ET
from datetime import datetime
import os
#import urllib3
##urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#import
import integration_module

log_file_location="log/log.txt"

if not os.path.exists(log_file_location):
    with open(log_file_location,"w") as file:
        file.write("")

def log_generation(ip,uid,message):
    log_file=open(log_file_location,"a")
    current=datetime.now()
    log_file.write(f"{current} {ip} {uid} {message} \n")

while True:
    
    config_file=ET.parse('config_srv.xml')
    config_data=config_file.getroot()
    current_time=datetime.now()
    print(current_time)
    for endpoint in config_data.find("reg_endpoint_details").findall("endpoint"):
        uid=endpoint.findtext("UID")
        last_seen=endpoint.findtext("last_update")
        ip=endpoint.findtext("last_ip")
        group=endpoint.findtext("last_group")
        current_status=endpoint.findtext("device_status")
        last_seen_t_format=datetime.fromisoformat(last_seen)
        differnce=(current_time - last_seen_t_format).total_seconds()
        
        if differnce > 90:
            device_status=endpoint.findtext("device_status")
            #print(device_status)
            if device_status == "online":
                log_generation(ip,uid,"device access has been revoked and change change to status to offline")
                print(f"{ip} online")
                if not ip.startswith("127.0.0."):
                    if group != None:
                        result = None
                        try:
                            print(f"this {ip} and {group}")
                            result,api_status_code=integration_module.device_delete(ip,group)

                            print(f"{ip} is online")
                        except Exception as error:
                            print(f"API push failed", error)
                        #print(result)
                        if result == None:
                            print("API unrachable")
                            pass 
                        elif result["status"] != "error":
                            print("changing to ofline")
                            device_status=endpoint.find("device_status")
                            device_status.text="offline"
                            ET.indent(config_file, space="    ", level=0)
                            config_file.write("config_srv.xml",encoding="utf-8",xml_declaration=True)
                        elif result["status"] == "error":
                            print("Failed to revoke the access")
                            print(result)
                    else:
                        pass

        else:
            pass

    print("sleeping")
    time.sleep(10)
    

# 
# https://www.plus2net.com/python/xml-configuration.php
# 
