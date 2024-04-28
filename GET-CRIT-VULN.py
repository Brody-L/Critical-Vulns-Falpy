# Get all critical level vulnerabilities for an organization using Falcon Spotlight
from datetime import datetime, timedelta
import json
import sys
import config
from falconpy import SpotlightVulnerabilities, Hosts
import pandas as pd
import dateparser
import typer

if not config.FALCON_CLIENT_ID or not config.FALCON_CLIENT_SECRET:
    raise ValueError("Please provide a valid Falcon Client ID and Client Secret in the config.py file")

# Initialize Spotlight service collection
falconSpot = SpotlightVulnerabilities(client_id=config.FALCON_CLIENT_ID,
                                  client_secret=config.FALCON_CLIENT_SECRET)

# initialize Hosts service collection
falconHost = Hosts(client_id= config.FALCON_CLIENT_ID,
              client_secret = config.FALCON_CLIENT_SECRET)

app = typer.Typer()

@app.command()
def retrieve_vulnerabilities(
        parent_children_report_csv_path: str, 
        start_date: str = '30 days ago', 
        output_filename: str = 'crit-vuln.json', 
        verbose: bool = False
):
    # date 30 days ago from today 
    _start_date = dateparser.parse(start_date)
    if not _start_date:
        raise ValueError('Invalid date format. Please use a valid date format like "2021-01-01"')

    # String w/ date for File Naming: <old date>--<today>
    # TODO this variable isn't used, is this copied from the other file and possibly not needed?
    hosts_from_dates = (f'{_start_date.strftime("%Y_%m_%d")}--{datetime.today().strftime("%Y_%m_%d_T%H-%M-%SZ")}')

    # Retrieve a list of active hosts in the last 30 days 
    hosts_search_result: dict = falconHost.query_devices_by_filter(filter=f"last_seen:>='{_start_date}'",limit=5000)

    # Isolate the device_ids into a list
    host_list = hosts_search_result['body']['resources']

    # Pull device details on each host_list device_id
    dev_details: dict = falconHost.get_device_details(ids=host_list)

    # Organize Device IDs with CIDs into dictionary
    resources = dev_details['body']['resources']
    cid_dict = {}
    for resource in resources:
        cid = resource['cid']
        device = resource['device_id']
        if cid not in cid_dict.keys():
            cid_dict[cid] = []
        if device not in cid_dict[cid]:
            cid_dict[cid].append(device)

    # Identify Spotlight Subscribers
    # May benefit from accessing a current parent_children_report via API 

    parent_children_report_csv_path = sys.argv[1]

    df = pd.read_csv(parent_children_report_csv_path)
    spot = df.loc[df['Falcon Module Subscriptions'].str.contains('Spotlight')] 

    # Spotlight Subscribers are placed in a list
    spotSubs = spot["CID String"].to_list()
    spotNames = spot["CID Name"].to_list()

    # # Subscriber CID:AID dictionary
    subCA = {}

    # Each subscribers AID is a new dictionary value under a CID key
    # Nested Dictionaries
    for (spotName, spotSub) in zip(spotNames, spotSubs):
        # set the CID to be a key with a list value
        subCA[f'{spotSub}'] = []
        # append the CID Name to the first item in the list
        subCA[f'{spotSub}'].append(spotName)
        # Make every AID associated with the CID its own dictionary with an empty list 
        # The empty list is where the Critical Vulns associated with an AID will be stored
        for x in range(len(cid_dict[f'{spotSub}'])):
            d = {}
            d[f'{cid_dict[spotSub][x]}'] = []
            subCA[f'{spotSub}'].append(d) 

    xAID = []
    for value in subCA.values():
        # TODO come up with better variable names for these loop variables based on what the actual data is
        for u,x in enumerate(value):
            if u == 0:
                continue
            for id in x.keys():
                xAID.append(id)
    dev_details2: dict = falconHost.post_device_details_v2(ids=xAID)

    for x in subCA.values():
        for a in x:
            if a == 0:
                continue
            for item in dev_details2['body']['resources']:
                if item['device_id'] == list(x[a].keys())[0]:
                    vuln_resource = {}
                    if 'hostname' in item:
                        vuln_resource['Hostname'] = item['hostname']

                    if 'os_product_name' in item:
                        vuln_resource['OS Product Name'] = item['os_product_name']
                                                            
                    if 'os_build' in item:
                        vuln_resource['OS Build'] = item['os_build']
                                                            
                    if 'last_login_user' in item:
                        vuln_resource['Last Login User'] = item['last_login_user']
                                                            
                    if 'system_manufacturer' in item:
                        vuln_resource['Manufacturer'] = item['system_manufacturer']
                                                            
                    if 'system_product_name' in item:
                        vuln_resource['Model'] = item['system_product_name']
                    vuln_resource['Critical CVE'] = {}
                    # TODO item access is making this better but it could be cleaner still
                    x[a][list(x[a].keys())[0]].append(vuln_resource)


    count = 0
    response: dict = falconSpot.query_vulnerabilities_combined(filter='cve.exprt_rating:"CRITICAL"',limit=1)
    size = response['body']['meta']['pagination']['total']
    after = response['body']['meta']['pagination']['after']
    lafter = response['body']['meta']['pagination']['after']

    while count <= size:
        # TODO define a PAGE_COUNT constant in the file, perhaps explain why 5000 is the limit
        response = falconSpot.query_vulnerabilities_combined(filter='cve.exprt_rating:"CRITICAL"',limit=5000,after=lafter)
        for m in range(len(response['body']['resources'])):
            if response['body']['resources'][m]['status'] == 'open':
                # AID
                # TODO  define a name for this constant 33
                rAID = response['body']['resources'][m]['aid'][33:]
                # CID
                rCID = response['body']['resources'][m]['cid']
                # CVE
                CVE = response['body']['resources'][m]['vulnerability_id']
                APP_PROD = response['body']['resources'][m]['apps'][0]['product_name_version']
                # Pagination
                lafter = response['body']['meta']['pagination']['after']
                for z in subCA[rCID]:
                    if isinstance(z,dict):
                        for key in z:
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


    if verbose:
        print(json.dumps(subCA,indent=2))
    output = open(output_filename,'w')
    output.write(json.dumps(subCA))
    output.close()
