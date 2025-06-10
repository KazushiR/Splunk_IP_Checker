# Splunk_IP_Checker
This script will log into the Splunk instance to check the search results of any ip addresses that the PFSense on the home network is communicating with. From there, it iterates through all possible IP addresses and then adds any that seem malicious and checks the IP address with AbuseAPDB API. If it goes over the thresh hold, it will add it to the list and after 24 hours, if there are any malicious IP Addresses, it will send myself an email. The reason there is 24 hours to send an email is due to the rate limit of ABUSEAPBD API. 

# Getting started
First, I looked at what I wanted to accomplish and to accomplish the use of some type of SIEM, I researched what type of SIEM that I can use. 
