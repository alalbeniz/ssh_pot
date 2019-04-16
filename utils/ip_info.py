import json
import requests
import sys

def get_ip_info_monapi(ip, proxy_conf=None):
    request_ip = requests.get("https://api.monapi.io/v1/ip/{}".format(ip))
    if request_ip.status_code == 200:
        ipinfo = json.loads(json.dumps(request_ip.json()))
        if ipinfo['iso_code'] and ipinfo['country']:
            return ipinfo
    return None


def get_ip_info_ipinfo(ip, proxy_conf=None):
    request_ip = requests.get("https://ipinfo.io/{}".format(ip))
    if request_ip.status_code == 200:
        ipinfo = json.loads(json.dumps(request_ip.json()))
        if not 'bogus' in ipinfo:
            return ipinfo
    return None


def insert_ip_info():
    ips = IP.select().where(IP.iso_code == None)
    for ip in ips:
        ipinfo = get_ip_info_monapi(ip.address)
        if ipinfo:
            ip.asn_organization = ipinfo['asn_organization']
            ip.asn_number       = ipinfo['asn_number']
            ip.threat_level     = ipinfo['threat_level']
            ip.city             = ipinfo['city']
            ip.region           = ipinfo['region']
            ip.latitude         = ipinfo['latitude']
            ip.longitude        = ipinfo['longitude']
            ip.country          = ipinfo['country']
            ip.iso_code         = ipinfo['iso_code']
            ip.postal_code      = ipinfo['postal']
            ip.blacklist_count  = ipinfo['blacklists_list_count']

            ip.save()

            for blacklist in ipinfo['blacklists']:
                ddbb_blacklist  = Blacklist.get_or_create(description=blacklist)
                IPBlacklist.create(IP=ip, blacklist=ddbb_blacklist).save()

            for threat in ipinfo['threat_class']:
                ddbb_threat     = Threat.get_or_create(description=threat)
                IPThreat.create(IP=ip, threat=ddbb_threat)

            #{'timezone': 'Australia/Sydney', 'asn_type': 'Content', 'longitude': 143.2104, 'city': None, 'asn_organization': 'Cloudflare, Inc.', 'threat_level': 'high', 'hostname': 'one.one.one.one', 'threat_class': ['organizations', 'malware', 'reputation'], 'iso_code': 'AU', 'country': 'Australia', 'blacklists': ['HPHOSTS_EMD', 'HPHOSTS_FSA', 'HPHOSTS_PSH', 'BITCOIN_NODES'], 'region': None, 'postal': None, 'latitude': -33.494, 'ip': '1.1.1.1', 'blacklists_list_count': 4, 'asn_number': 13335}
        else:
            ipinfo = get_ip_info_ipinfo(ip.address)
            if ipinfo:
                ip.city             = ipinfo['city']
                ip.region           = ipinfo['region']
                if ',' in ipinfo['loc']:
                    ip.latitude         = ipinfo['loc'].split(',')[0]
                    ip.longitude        = ipinfo['loc'].split(',')[0]
                ip.iso_code         = ipinfo['country']
                ip.asn_number       = ipinfo['']
                ip.asn_organization = ipinfo['']
                ip.save()
                #{'city': '', 'region': '', 'loc': '9.0000,-80.0000', 'ip': '141.98.81.100', 'country': 'PA', 'org': 'AS57043 HOSTKEY B.V.'}

        print('{} info updated'.format(ip.address))
    else:
        print('No ip information updated')


if __name__== "__main__":
    insert_ip_info()
