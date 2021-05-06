# DNSSpectre

Generate fake A, MX, NS, and SRV records to append to a preexisting zone file for 
Amazon Warehouse Services (AWS). Zone files, aka Start of Authority (SOA), records 
a domain’s DNS information to a text file. This script generates fake DNS records 
to increase the number of potential targets gathered from an unauthorized zone transfer 
or DNS request. The goal is to decieve attackers into making DNS requests/ping sweep of 
non-existent systems.

The more valid IP addresses the better!

#### Record Types
- An SRV record or service record matches up a specific service that runs on your domain or subdomain to a target domain. This allows you to direct traffic for specific services, like instant messaging to another server. 

- An A record points your domain or subdomain to your public IPv4 address, which allows web traffic to reach your EC2 instance/domain.

- An MX record or mail exchanger record sets the mail delivery destination for a domain or subdomain. 

- NS records or name server records set the nameservers for a domain or subdomain. The primary nameserver records for your domain are set both at your registrar and in your zone file.

Reference: https://www.linode.com/docs/guides/dns-records-an-introduction/


#### Execution
 <pre><code>python DNSSpecter.py -path C:path\DNSRecords.txt -ip 000.000.000  123.123.123.123 456.456.456.456</code></pre>
 <pre><code>python DNSSpecter.py -path C:path\DNSRecords.txt -ip 000.000.000 -num 3  -upload -host_id XXXXXXXXXXXXXXX</code></pre>
 
 
 #### Command Line Interface Options
- path : (REQUIRED) Path to prexisting text or json zone file. This code assumes there is only one SOA, A, and NS DSN record in the zone file. Be mindful that spaces in the path's directory names will trigger errors in the AWS CLI
- ip: (REQUIRED) one or more space separated valid IPv4 addresses
- num: integer for the number of records to generate for each valid and unused public IPv4 address
- upload: flag to upload records into the new hosted zone, using the AWS CLI command. AWS CLI must be installed
- host_id: Hosted Zone ID, required parameter for uploading generated DNS records into AWS Hosted Zone


#### Output
Saves json of generated DNS records to the same path as the input zone file. Optionally save the json and upload it to the hosted zone using the AWS CLI
