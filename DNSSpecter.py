"""
Author: Green Winters
Name: DNS Spectre (AWS ver)

Generate fake A, MX, NS, and SRV records to append to a preexisting zone file for 
Amazon Warehouse Services (AWS). Zone files, aka Start of Authority (SOA), records 
a domain’s DNS information to a text file. This script generates fake DNS records 
to increase the number of potential targets gathered from an unauthorized zone transfer 
or DNS request. The goal is to decieve attackers into making DNS requests/ping sweep of 
non-existent systems.

The more valid IP addresses the better!

Record Types
-----------
An SRV record or service record matches up a specific service that 
runs on your domain or subdomain to a target domain. This allows 
you to direct traffic for specific services, like instant messaging, 
to another server. 

An A record points your domain or subdomain to your public IPv4 address, 
which allows web traffic to reach your EC2 instance/domain.

An MX record or mail exchanger record sets the mail delivery destination 
for a domain or subdomain. 

NS records or name server records set the nameservers for a domain or subdomain. 
The primary nameserver records for your domain are set both at your registrar and 
in your zone file.

Reference: https://www.linode.com/docs/guides/dns-records-an-introduction/


Parameters
----------
path : Path to prexisting text or json zone file. This code assumes there is only one 
    SOA, A, and NS DSN record in the zone file. Be mindful that spaces in the path's directory names
    will trigger errors in the AWS CLI
ip: one or more space separated valid IPv4 addresses
num: integer for the number of records to generate for each valid and unused public IPv4 address
upload: flag to upload records into the new hosted zone, using the AWS CLI command. 
    AWS CLI must be installed
host_id: Hosted Zone ID, required parameter for uploading generated DNS Records into AWS Hosted Zone


Output
------
Saves json of generated DNS records to the same path as the input zone file. Optionally 
save the json and upload it to the hosted zone using the AWS CLI


"""
import json
import random
import re
import argparse
import os
import sys
import subprocess

# Parse named command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-path", "-p",type=str, required = True,
                    help="the path to zone file")
parser.add_argument("-ip", "-ip",type=str, nargs="+", required = True,
                    help="space separated ip address(es) used to generate fake DNS records to")
parser.add_argument("-num", "-n",type=int,
                    help="Number of records to generate per IP address. Must be equal to or less than 34")
parser.add_argument("-upload", "-u",action="store_true", 
                    help= "Upload generated records into hosted zone using AWS CLI commands")
parser.add_argument("-host_id", "-id",type = str,
                    help= "Hosted Zone ID, required parameter for AWS Hosted Zone. Must be provided with upload flag")

args = parser.parse_args()

inputPath = args.path
inputIP = args.ip

if args.num is not None:
    assert args.num <= 34, "Number of records passed is greater than 34. Give a integer less than or equal to 34."
    numRec = args.num
else:
    numRec = random.randint(0, 34) # Generate a random number of records if none is passed to CLI


f = open(inputPath,) # Open JSON file
data = json.load(f) # returns JSON/txt file as a dictionary


for i in data["ResourceRecordSets"]:
    if i["Type"]=="SOA":
        domainName = i["Name"][:-1] # Get the first and second level domain name for fake record generation
    if i["Type"]=="NS":
        NSRecord = i # Get Domain's NS Record
    if i["Type"]=="A":
        baseDomain = i

# Options for third level domains
thirdLevelDomain = ["mail", "blog", "webmail", "server", "ns1", "smtp", 
"secure", "vpn", "beta", "shop", "ftp", "mail2", "test", "portal", "admin", 
"host", "support", "dev", "web", "imap", "cloud", "_service._protocol.",
"forum", "wiki", "help", "admin", "store", "mx1", "pop", "api", "exchange", 
"app", "news", "m"]

def generateDNSRecords(inputIP: list, n: int, subDomainList: list,
 domainName: str, NSRecord:dict, baseDomain:dict):
    """
    Generate SVR, MX, NS, and/or A records using list of subdomains and ip addresses

    Parameters
    ----------
    inputIP: list of valid public ipv4 addresses
    n: integer number that represents how many records to generate for each ip address
    subDomainList : list of third level domain prefixes
    domainName: the input zone file's second and first level domain e.g. example.com, book.net
    NSRecord: the input's zone file's NS record

    Output
    ------
    List of dictionaries. Each dictionary represents a fake DNS record formatted to be imported
    into AWS as a zone file
    """
    thirdDomainDict = {}
    for fakeIP in inputIP:
        selectedSubDomain = random.choices(subDomainList, k=n)
        for subDomain in selectedSubDomain:
            if subDomain in ["mail","webmail"]:
                thirdDomainDict[subDomain] = {
                    #Create a Mail Exchanger Record
                    "Action": "CREATE",
                    "ResourceRecordSet":
                    {
                        "Name": domainName,
                        "Type": "MX",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": subDomain + "."+ domainName}]
                    },
                    # MX Records need to have its own 'A' record that resolves to valid IP address
                    # 'A' Records require AliasTarget, all of [TTL and ResourceRecords], or 
                    # TrafficPolicyInstanceId
                    "Action": "CREATE",
                    "ResourceRecordSet":
                    {
                        "Name": subDomain + "." + domainName,
                        "Type": "A",
                        "ResourceRecords": [{"Value": fakeIP}],
                        "TTL": 300
                    }
                }
            elif subDomain == "_service._protocol.":
                protocolDict = {"udp":[5298,3478], "tcp":[5223,5222, 5269,5280,5298]}
                protocol, port_list = random.choice(list(protocolDict.items()))
                if len(port_list) > 1:
                    port = random.choice(port_list)
                thirdDomainDict[subDomain] = {
                    "Action": "CREATE",
                    "ResourceRecordSet":
                    {
                        "Name": "_xmpp-client."+protocol+ "."+domainName+".",
                        # Extensible Messaging and Presence 
                        # Protocol (XMPP) is an open XML technology 
                        # for real-time communication.
                        "Type": "SRV",
                        "TTL": 86400,
                        "ResourceRecords": [{"Value": "1 10 " + str(port)+ " slack."+domainName}]
                    }
                }
                """ 
                For a SRV record, values = 
                    - priority (priority of the target host, lower value means more preferred),
                    - weight (A relative weight for records with the same priority.),
                    - port (TCP or UDP port on which the service is to be found), and
                    - target (the canonical hostname of the machine providing the service)
                """
            elif subDomain in ["shop", "forum", "wiki","store","news"]:
                """ 
                    NS records or name server records set the nameservers for a domain 
                    or subdomain. The primary nameserver records for your domain are set 
                    both at your registrar and in your zone file
                    
                    Subdomain nameservers get configured in the primary domain’s zone file
                """
                # Extract and reuse DNS's NS addresses
                # NSRecord["ResourceRecords"] should be a list of dictionaries with one key, one NS address
                NS_list = [NS for val in NSRecord["ResourceRecords"] for key, NS in val.items()]
                NS_Address = [subaddy for addy in NS_list for subaddy in re.findall(r"(?<=awsdns).*", addy)]
                # Generate a NS record for a legit subdomain site
                thirdDomainDict[subDomain] = {
                    #Create Name Server Record
                    "Action": "CREATE",
                    "ResourceRecordSet":
                    {
                        "Name": subDomain + "." + domainName,
                        "Type": "NS",
                        "TTL": 3600,
                        "ResourceRecords": [{"Value":"ns-" + str(random.randint(10, 2000)) + ".awsdns" + partialNS } for partialNS in NS_Address]
                        # Need atleast two entries
                    }
                }
            else:
                #Create an "A" Record
                thirdDomainDict[subDomain] = {
                    # Generate A record that resolves to unused IP address
                    "Action": "CREATE",
                    "ResourceRecordSet":
                    {
                        "Name": subDomain + "." + domainName,
                        "Type": "A",
                        "ResourceRecords": [{"Value": fakeIP}],
                        "TTL": 300
                    }
                }    
    '''
    To find the correct AWS DSNName:
        * Open the Amazon EC2 console
        * In the navigation pane, choose Instances. 
        * Select your instance from the list. 
        * In the details pane, the Public DNS (IPv4) and Private DNS 
        fields display the DNS hostnames
    '''
    output = {"Changes": list(thirdDomainDict.values())} 
    
    return output


def saveToPath(records: dict, path_flag = False):
    """
    Save a json formatted version of the generated records to disk
    """
    outputPath = os.path.dirname(inputPath) + "//updatedDNSrecords.txt"
    with open(outputPath, "w") as jsonobj:
        json.dump(records, jsonobj)
        jsonobj.write('\n')
    
    if path_flag==True:
        return outputPath


addRecords = generateDNSRecords(inputIP, numRec,thirdLevelDomain, domainName, NSRecord, baseDomain)

if not args.upload:
    saveToPath(addRecords)

if args.upload:
    filePath = saveToPath(addRecords, True)
    execResult = subprocess.run(["aws","route53", "change-resource-record-sets", "--hosted-zone-id", args.host_id, "--change-batch", "file://"+filePath],
    capture_output=True)
    if execResult.returncode == 0:
        print("\nSuccessful Update")
        print(execResult.stdout.decode("utf-8"))
    else:
        print("\nUnsuccessful Update\n")
        print(execResult.stderr.decode("utf-8"))