# Critical-Vulns-Falconpy
The main script CRIT-VULN.py will JSON fromat all the critical vulnerabilities and the effected products of each Asset ID for a list of Customer IDs

## Output Format: 
```
{
  "<CID STRING - Parent>": [
    "<CID NAME - Parent>"
  ],
  "<CID STRING - Child 0>": [
    "<CID NAME - Child 0>",
    {
      "<AID 0>": [
        {
          "Hostname": "",
          "OS Product Name": "",
          "OS Build": "",
          "Last Login User": "",
          "Manufacturer": "",
          "Model": "",
          "Critical CVE": {
            "CVE-0000-0000": [
              "<Affected Product>"
            ]
          }
        }
      ]
    },
  ]
}
```

## Install Falconpy and dependencies:
`python3 -m pip install crowdstrike-falconpy pandas`

## Export Parent_Child_Report from the Falcon Flight Control Module
The report contains Spotlight Subscriber information under the Falcon Module Subscriptions column

## Usage: 
`python CRIT-VULN.py parent_child_report_<date>.csv`
