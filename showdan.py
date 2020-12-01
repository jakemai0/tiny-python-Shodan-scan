#!/usr/bin/python3

"""
A Shodan/ZoomEye scan for IP range (potentially reverse DNS lookup)
Needs to install shodan through pip: python3 -m pip3 install shodan
Needs to install zoomeye through pip: python3 -m pip3 install zoomeye-sdk
"""

import shodan
import zoomeye
import sys
import time
import ipaddress as ipadd


SHODAN_API_KEY = ''  # Shodan api key here
ZOOMEYE_API_KEY = ''  # Zoomeye api key here
shodan_api = shodan.Shodan(SHODAN_API_KEY)
zoomeye_api = zoomeye.ZoomEye(api_key=ZOOMEYE_API_KEY)


# Check usage
def check():
    if len(sys.argv) != 2:
        print("Invalid argument!")
        print("Usage: " + sys.argv[0] + " \"valid IPv4 address or IPv4 Range in CIDR Notation\"")
        sys.exit()


def scan():
    # Take arg and convert CIDR to IP addresses
    ipRange = sys.argv[1]
    try:
        for eachIP in ipadd.IPv4Network(ipRange):
            print("\nSCANNING: "+str(eachIP))
            print("*"*22+" SHODAN RESULT "+"*"*22)
            # Pulling Shodan API data
            try:
                host = shodan_api.host(str(eachIP))

                # More fields can be added here if more information is desired
                print("""IP: {} \nOpen Ports: {} \nOrganization: {} \nOperating System: {}\n"""
                        .format(host['ip_str'], host['ports'], host.get('org', 'n/a'), host.get('os', 'n/a')))

                for item in host['data']:
                    print("""Port: {} \nBanner: {}""".format(item['port'], item['data']))
                    try:
                        print("Organisation: {}".format(item['ssl']['cert']['subject']['O']))
                    except Exception:
                        pass
                time.sleep(1)
            except shodan.APIError as e:
                print("{}".format(e))
                time.sleep(1)
                pass

            # Pulling ZoomEye API data
            data = zoomeye_api.dork_search(eachIP)
            print("*"*22+" ZOOMEYE RESULT "+"*"*22)

            for item in data:
                if (len(str(item['portinfo'])) > 200):
                    print("""Port: {}\nHostname: {}\nVersion: {}\nService: {}\nDevice: {}\nExtra Info: {}\nOS: {}\nApp Title: {}\nBanner: {}""".format(item['portinfo']['port'], item['portinfo']['hostname'], item['portinfo']['version'], item['portinfo']['service'], item['portinfo']['device'], item['portinfo']['extrainfo'], item['portinfo']['os'], item['portinfo']['app'], item['portinfo']['banner']))
                else:
                    print("No information available for that IP.")

    # Catch error when provided IP is invalid
    except ipadd.AddressValueError as e:
        print("Invalid IP: {}".format(e))
        sys.exit()

    print("\nSCAN COMPLETED!   ¯\_(ツ)_/¯   ")


if __name__ == '__main__':
    check()
    scan()

'''
To be implemented:
SecurityTrails? DNS reverse lookup mode?
'''
