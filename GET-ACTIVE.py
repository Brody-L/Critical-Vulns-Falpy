# Tasks 1: Retrieve a list of all device that have been active over the last 30 days by customer

from datetime import datetime, timedelta
import json
import config
from falconpy import Hosts
import typer
import dateparser

app = typer.Typer()

# initialize Hosts service collection
falcon = Hosts(client_id= config.FALCON_CLIENT_ID,
              client_secret = config.FALCON_CLIENT_SECRET)

@app.command()
def retrieve_vulnerabilities(old_date: str, output_file_name: str = ''):
    # date 30 days ago from today 
    start_date = dateparser.parse(old_date)
    if not start_date:
        raise ValueError('Invalid date format. Please use a valid date format like "2021-01-01"')
    
    start_date_string = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    # String w/ date for File Naming: <old date>--<today>
    hosts_from_dates = (f'{start_date.strftime("%Y_%m_%d")}--{datetime.today().strftime("%Y_%m_%d_T%H-%M-%SZ")}')

    # Retrieve a list of active hosts in the last 30 days 
    # TODO we should figure out types for this result
    hosts_search_result: dict = falcon.query_devices_by_filter(filter=f"last_seen:>='{start_date_string}'",limit=5000)

    # Isolate the device_ids into a list
    host_list = hosts_search_result['body']['resources']

    # Pull device details on each host_list device_id
    dev_details: dict = falcon.get_device_details(ids=host_list)

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

    # Write the cid_dict to a file in json format
    _output_file_name = output_file_name if output_file_name else f'CID_DEV_{hosts_from_dates}.json'
    cid_device = open(_output_file_name,'w')
    cid_device.write(json.dumps(cid_dict,indent=2))
    cid_device.close

    # There is now a file with the format 'CID_DEV_<old date>--<today's date>.json'


if __name__ == "__main__":
    app()
