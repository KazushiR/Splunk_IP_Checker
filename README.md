# Splunk_IP_Checker
This script will log into the Splunk instance to check the search results of any ip addresses that the PFSense on the home network is communicating with. From there, it iterates through all possible IP addresses and then adds any that seem malicious and checks the IP address with AbuseAPDB API. If it goes over the thresh hold, it will add it to the list and after 24 hours, if there are any malicious IP Addresses, it will send myself an email. The reason there is 24 hours to send an email is due to the rate limit of ABUSEAPBD API. 

# Getting started
First, I looked at what I wanted to accomplish and to accomplish the use of some type of SIEM, I researched what type of SIEM that I can use. I had to look into budge constraints and looked at three possible options of either Security Oinion, ELK Stack, or Splunk. I researched each SIEM based on their ease of use, setup, and cost. I determined that Splunk was the right choice that fit all three categories as well as the use of Python integration into the environment.
I installed Splunk, went through the set up process. Next, I had to research what type of Firewall I needed to use in order to best serve in getting logging data I can use to integrate into the SIEM.

# Environment set up
After researching the best logging data, I decided to purchase a Netgate PFsense firewall into my network, as this had the perfect CLI use, logging and was very versatile in what it can do as well as the cost effeciency of the product. The size of the product was well perfect for my home and switch. I didn't need to go through with making an virtual PF Sense firewall and I will have more control over what comes through my network. From there,  

![image](https://github.com/user-attachments/assets/1eb7e1ec-d0d4-4843-ace9-460b0bd22770)


Netgate 1100
