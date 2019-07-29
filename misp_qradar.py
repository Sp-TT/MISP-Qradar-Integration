#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Spencer Tang
# Date: 26/07/2019
# Comment: This script is fethcing data from MISP and ingest into IBM Qradar
import json
from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import requests
import sys
import time
import re
import socket
import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

misp_auth_key = "YOUR MISP KEY"
qradar_auth_key = "YOUR QRADAR AUTHKEY"
#qradar_ref_set = "MISP_IP"
qradar_ref_set = "MISP_OTHERS"
misp_server = "MISP SERVER IP"
qradar_server = "QRADAR SERVER IP"
frequency = 60 # In minutes

#------*****------#

QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set

QRadar_headers = {
    'sec': qradar_auth_key,
    'content-type': "application/json",
    }

def validate_refSet():
    validate_refSet_url = "https://" + qradar_server + "/api/reference_data/sets/" + qradar_ref_set
    validate_response = requests.request("GET", validate_refSet_url, headers=QRadar_headers, verify=False)
    print (time.strftime("%H:%M:%S") + " -- " + "Validating if reference set " + qradar_ref_set + " exists")
    if validate_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Validating reference set " + qradar_ref_set + " - (Success) ")
        validate_response_data = validate_response.json()
        refSet_etype = (validate_response_data["element_type"])
        print(refSet_etype)
        print(time.strftime("%H:%M:%S") + " -- " + "Identifying Reference set " + qradar_ref_set + " element type")
        print(time.strftime("%H:%M:%S") + " -- " + "Reference set element type = " + refSet_etype + " (Success) ")
        if refSet_etype == "IP":
            print (time.strftime("%H:%M:%S") + " -- " + "The QRadar Reference Set " + qradar_ref_set + " Element Type = \"IP\". Only IPs will be imported to QRadar and the other IOC types will be discarded")
            get_misp_data(refSet_etype)
        else:
            get_misp_data(refSet_etype)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "QRadar Reference Set does not exist, please verify if reference set exists in QRadar.")
        sys.exit()

def qradar_post_IP(ioc_cleaned_data, ioc_count_cleaned):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=ioc_cleaned_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Imported " + str(ioc_count_cleaned) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")

def qradar_post_all(import_data, ioc_count):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=import_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + " (Finished) Imported " + str(ioc_count) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")

def socket_check_qradar():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to QRadar")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((qradar_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to QRadar")
        socket_check_misp()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to QRadar, Please check connectivity before proceeding.")

def socket_check_misp():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to MISP")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((misp_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to MISP")
        validate_refSet()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to MISP Server, Please check connectivity before proceeding.")


def get_misp_data(refSet_etype): #this function will get misp data for last 1 day)
    
    global network_ip, network_domain
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    result = misp.search(publish_timestamp="5d", pythonify=True)
    network_ip = []
    network_domain = []
    s=""

    if not result:
        print('No results for that time period')
        exit(0)

    for r in result:
        s = r.to_json()
        json_data = json.loads(s)
        for attribute in json_data["Event"]["Attribute"]:
            iocs = attribute["value"]
            if attribute["type"] in ("ip-src", "ip-dst"):
                network_ip.append(iocs)
            elif attribute["type"] in ("domain", "url"):
                network_domain.append(iocs)
            else:
                continue


    if refSet_etype == "IP":
        ingest_ip_data = json.dumps(network_ip)
        ioc_ip_count = len(network_ip)
        print(time.strftime("%H:%M:%S") + " -- " + "Trying to clean the IOCs to IP address, as " + qradar_ref_set + " element type = IP")
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) Extracted " + str(ioc_ip_count) + " IPs from initial import.")
        qradar_post_IP(ingest_ip_data, ioc_ip_count)
    else:
        ingest_domain_data = json.dumps(network_domain)
        ioc_domain_count = len(network_domain)
        print(time.strftime("%H:%M:%S") + " -- " + "Trying to clean the IOCs to Domain, as " + qradar_ref_set + " element type = AlphaNumeric")
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) Extracted " + str(ioc_domain_count) + " Domains from initial import.")

        qradar_post_all(ingest_domain_data, ioc_domain_count)

