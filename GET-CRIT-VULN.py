# Get all critical level vulnerabilities for an organization using Falcon Spotlight
from datetime import datetime, timedelta
import json
import config
from falconpy import SpotlightVulnerabilities, Hosts
import pandas as pd

# Initialize Spotlight service collection
falconSpot = SpotlightVulnerabilities(client_id=config.FALCON_CLIENT_ID,
                                  client_secret=config.FALCON_CLIENT_SECRET)

# initialize Hosts service collection
falconHost = Hosts(client_id= config.FALCON_CLIENT_ID,
              client_secret = config.FALCON_CLIENT_SECRET)

# date 30 days ago from today 
last_30_days = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

# String w/ date for File Naming: <old date>--<today>
hosts_from_dates = (f'{(datetime.today() - timedelta(days=30)).strftime("%Y_%m_%d")}--{datetime.today().strftime("%Y_%m_%d_T%H-%M-%SZ")}')

# Retrieve a list of active hosts in the last 30 days 
hosts_search_result = falconHost.query_devices_by_filter(filter=f"last_seen:>='{last_30_days}'",limit=5000)

# Isolate the device_ids into a list
host_list = hosts_search_result['body']['resources']

# Pull device details on each host_list device_id
dev_details = falconHost.get_device_details(ids=host_list)

# Organize Device IDs with CIDs into dictionary
resources = dev_details['body']['resources']
cid_dict = {}
for i in range(len(resources)):
    cid = resources[i]['cid']
    device = resources[i]['device_id']
    if cid not in cid_dict.keys():
        cid_dict[cid] = []
    if device not in cid_dict[cid]:
        cid_dict[cid].append(device)

# Identify Spotlight Subscribers
# May benefit from accessing a current parent_children_report via API 
df = pd.read_csv('<spotlight subscribers csv>')
spot = df.loc[df['Falcon Module Subscriptions'].str.contains('Spotlight')] 

# Spotlight Subscribers are placed in a list
spotSubs = spot["CID String"].to_list()
spotNames = spot["CID Name"].to_list()

# # Subscriber CID:AID dictionary
subCA = {}

# Each subscribers AID is a new dictionary value under a CID key
# Nested Dictionaries
for i in range(len(spotNames)):
    # set the CID to be a key with a list value
    subCA[f'{spotSubs[i]}'] = []
    # append the CID Name to the first item in the list
    subCA[f'{spotSubs[i]}'].append(spotNames[i])
    # Make every AID associated with the CID its own dictionary with an empty list 
    # The empty list is where the Critical Vulns associated with an AID will be stored
    for x in range(len(cid_dict[f'{spotSubs[i]}'])):
        d = {}
        d[f'{cid_dict[spotSubs[i]][x]}'] = []
        subCA[f'{spotSubs[i]}'].append(d) 

xAID = []
for k,v in subCA.items():
    for u in range(len(subCA[k])):
        if u == 0:
            continue
        for key,val in subCA[k][u].items():
            xAID.append(key)
dev_details2 = falconHost.post_device_details_v2(ids=xAID)

for c in subCA.keys():
    for a in range(len(subCA[c])):
        if a == 0:
            continue
        for item in range(len(dev_details2['body']['resources'])):
            if dev_details2['body']['resources'][item]['device_id'] == list(subCA[c][a].keys())[0]:
                j = {}
                if 'hostname' in dev_details2['body']['resources'][item]:
                    j['Hostname'] = dev_details2['body']['resources'][item]['hostname']

                if 'os_product_name' in dev_details2['body']['resources'][item]:
                    j['OS Product Name'] = dev_details2['body']['resources'][item]['os_product_name']
                                                        
                if 'os_build' in dev_details2['body']['resources'][item]:
                    j['OS Build'] = dev_details2['body']['resources'][item]['os_build']
                                                        
                if 'last_login_user' in dev_details2['body']['resources'][item]:
                    j['Last Login User'] = dev_details2['body']['resources'][item]['last_login_user']
                                                        
                if 'system_manufacturer' in dev_details2['body']['resources'][item]:
                    j['Manufacturer'] = dev_details2['body']['resources'][item]['system_manufacturer']
                                                        
                if 'system_product_name' in dev_details2['body']['resources'][item]:
                    j['Model'] = dev_details2['body']['resources'][item]['system_product_name']
                j['Critical CVE'] = {}
                subCA[c][a][list(subCA[c][a].keys())[0]].append(j)


count = 0
response = falconSpot.query_vulnerabilities_combined(filter='cve.exprt_rating:"CRITICAL"',limit=1)
size = response['body']['meta']['pagination']['total']
after = response['body']['meta']['pagination']['after']
lafter = response['body']['meta']['pagination']['after']

while count <= size:
    response = falconSpot.query_vulnerabilities_combined(filter='cve.exprt_rating:"CRITICAL"',limit=5000,after=lafter)
    for m in range(len(response['body']['resources'])):
        if response['body']['resources'][m]['status'] == 'open':
            # AID
            rAID = response['body']['resources'][m]['aid'][33:]
            # CID
            rCID = response['body']['resources'][m]['cid']
            # CVE
            CVE = response['body']['resources'][m]['vulnerability_id']
            APP_PROD = response['body']['resources'][m]['apps'][0]['product_name_version']
            # Pagination
            lafter = response['body']['meta']['pagination']['after']
            for z in range(len(subCA[rCID])):
                if isinstance(subCA[rCID][z],dict):
                    for key in subCA[rCID][z]:
                        if key == rAID:
                            # Check if the CVE is already a key, if it is then append the APP_PROD
                            if CVE in subCA[rCID][z][rAID][0]['Critical CVE']:
                                # Check that APP_PROD isn't already in CVE
                                if APP_PROD not in subCA[rCID][z][rAID][0]['Critical CVE'][CVE]:
                                    subCA[rCID][z][rAID][0]['Critical CVE'][CVE].append(APP_PROD)
                            # If CVE is not already a key, initialize it now. Then append APP_PROD
                            else:
                                subCA[rCID][z][rAID][0]['Critical CVE'][CVE] = []
                                subCA[rCID][z][rAID][0]['Critical CVE'][CVE].append(APP_PROD)

        count += 1


# print(json.dumps(subCA,indent=2))
output = open('crit-vuln.json','w')
output.write(json.dumps(subCA))
output.close()