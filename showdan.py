#!/usr/bin/python3

"""

A Shodan scan for IP range
Needs to install shodan through pip: python3 -m pip3 install shodan

"""

import shodan
import sys
import time
import ipaddress as ipadd

API_KEY='KguYx2uMOscmpNdoyaptzWFrTWxFxzg6' # Jake's key, can use ya own if ya want
api=shodan.Shodan(API_KEY)

def check():
    if len(sys.argv)==1:
        print("Must enter ip/or ip range")
        sys.exit()

def scan():
    # Take arg and convert CIDR to IP addresses
    ipRange=sys.argv[1]
    try:
        for eachIP in ipadd.IPv4Network(ipRange):
            try:
                print("Scanning: "+str(eachIP))
                
                # Pulling API data
                host=api.host(str(eachIP))
                print("*"*60)

                # More fields can  be add here if more information is desired
                print("""IP: {} \nOpen Ports: {} \nOrganization: {} \nOperating System: {}\n"""
                        .format(host['ip_str'],host['ports'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                for item in host['data']:
                    print("""Port: {} \nBanner: {}""".format(item['port'], item['data']))
                    try:
                        print("Organisation: {}".format(item['ssl']['cert']['subject']['O']))
                        print("*"*60)
                    except:
                        pass
                time.sleep(1)

            except shodan.APIError:
                time.sleep(1)
                pass
    except ipadd.AddressValueError as e:
        print("Invalid IP: {}".format(e))
        sys.exit()

    print("Shodan scan completed!")

if __name__=='__main__':
    check()
    scan()



'''
To be implemented:
ipinfo.io? ip info
greynoise? ip info
SecurityTrails? DNS reverse lookup
ZoomEye? host info


'''
