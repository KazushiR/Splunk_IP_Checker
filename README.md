# Splunk_IP_Checker
This script will log into the Splunk instance to check the search results of any ip addresses that the PFSense on the home network is communicating with. From there, it iterates through all possible IP addresses and then adds any that seem malicious and checks the IP address with AbuseAPDB API. If it goes over the thresh hold, it will add it to the list and after 24 hours, if there are any malicious IP Addresses, it will send myself an email. The reason there is 24 hours to send an email is due to the rate limit of ABUSEAPBD API. 

# Getting started
First, I looked at what I wanted to accomplish and to accomplish the use of some type of SIEM, I researched what type of SIEM that I can use. I had to look into budge constraints and looked at three possible options of either Security Oinion, ELK Stack, or Splunk. I researched each SIEM based on their ease of use, setup, and cost. I determined that Splunk was the right choice that fit all three categories as well as the use of Python integration into the environment.
I installed Splunk, went through the set up process. Next, I had to research what type of Firewall I needed to use in order to best serve in getting logging data I can use to integrate into the SIEM.

# Environment set up
After researching the best logging data, I decided to purchase a Netgate PFsense firewall into my network, as this had the perfect CLI use, logging and was very versatile in what it can do as well as the cost effeciency of the product. The size of the product was well perfect for my home and switch. I didn't need to go through with making an virtual PF Sense firewall and I will have more control over what comes through my network. From there,  

![image](https://github.com/user-attachments/assets/1eb7e1ec-d0d4-4843-ace9-460b0bd22770)


Netgate 1100

I set up my Splunk environment on a Ubuntu Mini PC with basic capabilities as it was used for other purposes for home automation. I was then able to set up the Splunk instance on my home network per below.

![image](https://github.com/user-attachments/assets/7656458a-7101-412e-b137-f36223a241a2)
Screenshot of my Splunk instance.

After careful research, I figured out how to send logs from the PFSense to the Splunk instance to aggregate the logs into the SIEM (Security Information and Event Management). First, I had to find the IP address of my Ubuntu Server and then afterwards, I designated a port number to send the logs to. I decided to use the default port of 514 which is the Syslog protocol. Afterwards, I inputted that into my PFsense in the forwarding options per below.

![image](https://github.com/user-attachments/assets/47b395bf-fdd6-4381-bf5b-0141d2bdc473)
Where the System Logs are located within PFSense

![image](https://github.com/user-attachments/assets/cdec33c7-a7c5-4b5c-87ff-f620cc8cba5a)
Remote logging option within PFSense

After setting this up, I had to research how to receive traffic to the Splunk Instance. From there, I had to create an index receiver to receive logs and an index to store the logs in the Ubuntu Server.

![image](https://github.com/user-attachments/assets/38237034-6444-4f3a-99bf-69d0f7771dce)
Splunk Input to receive logs in a UDP form.

![image](https://github.com/user-attachments/assets/97a4d499-f0f6-4dad-8c6b-0c64c2d01538)
Indexes to place the logs from the PF Sense and store it in the Ubuntu Mini Computer

![image](https://github.com/user-attachments/assets/4c03b1d8-a6bb-4dc1-b2c1-f528f0231a41)
Going into Search bar within Splunk and I can search through the IP addresses listed.

After going through a lengthy process, the hard part was done in terms of setting up the equipment to help receive logs. The difficulty laid in going into the PFSense and finding the correct settings. From there, I had to mess around to find the correct port and ip address. Next part should be an easier process but a lengthier time to implement. Thankfully, I can use other tools to help to look up errors when creating the code for Splunk. The main tool that I used primarily was Chatgpt to look up error codes when looking at the code. I mainly used that as a way to find why my code wasn’t working.

I first researched what scripting library to use to connect to the Splunk instance to get the code. I found out that I had to use a library called Splunk Library. This is the first part of the process where I had trouble connecting to the Splunk server. I couldn’t find any documentation on this and after going through everything, I was at my wits end. I finally decided to try using ChatGPT and they recommended client.service() to connect to Splunk and put the data in Json format to easily sparse through the data itself.

![image](https://github.com/user-attachments/assets/4d5434f9-f951-4cae-ac2a-c27e0a100954)
Putting my Password and username in an environmental variable for security reasons.

![image](https://github.com/user-attachments/assets/b745662f-0dad-4593-9920-bb6521559654)
Connecting to Splunk and running a search query

I then created a global variable to put into my “Search_parametere()” definition so I can store the ip addresses to be used in a later definition. I then ran a regex search query after finding the necessary data. The problem was that each data had additional information and the data I needed was just the IP addresses. After making a regex search query, I loaded up the ip addresses into “global_destination” so that way I can iterate through the list to find malicious IP addresses.

![image](https://github.com/user-attachments/assets/2694caa8-6121-41db-8f63-caed97cfe3d4)
Regex search query to find IP addresses.

After getting the ip addresses, I had to research how to use the IP addresses to look up malicious IP’s. After digging around, I found the AbuseIPDB API. After looking around, it will allow me to look up ip addresses and see what the score or the likelyhood of a malicious IP. The good thing with this API is that it allows me a search query of 1000 look ups a day for free.

![image](https://github.com/user-attachments/assets/632cbf2e-d1ac-4e9a-8b33-410118e4ebfb)
AbusePDB API

![image](https://github.com/user-attachments/assets/12dd3c0c-8723-4550-a24e-155e15d08991)
Rate Limit of the AbusePDB

![image](https://github.com/user-attachments/assets/cf641fb7-8b3f-4f57-86af-5a484911c978)
Example of data sent to me with the primary concern of using the “Confidence of Abuse” score

After setting up my account and getting the Client ID and Secret Key from AbusePDB, I connected my script to their API service and was able to start iterating through the list of IP addresses in “Destination_IP” list per below. I iterated through it, put it into a json format and then found the confidence score of an abusive IP address.

![image](https://github.com/user-attachments/assets/c566f56d-8425-43a9-877e-4ce1faa9dcca)
Using the “global_Dest” list and querying the ip address to get information from AbusePDB

After sending in the request, I was able to get the confidence score and a wide variety of other information. inputted into a string called “full_message” so I can get all the details within the string for easier time to read. If it is above 85%, the script will get the “full_message” variable and connect to my email system and send me a list of potential malicious IP addresses in an email format so I can look into it further.

![image](https://github.com/user-attachments/assets/f8bee049-21a6-4a29-92d0-e29fe0f6f409)
Getting the necessary information to put into the email

![image](https://github.com/user-attachments/assets/8aa4ec33-fa98-4f03-a560-c913a93c9b72)
Appending the each malicious ip addresses into the “message” variable to aggregate all ip addresses and send me an email.


# Conclusion

I had to keep this code continuously running in my Ubuntu server to make this work 24 hours a day. Of course since I have a rate limit from AbusePDB, I had to put limitations on how many times I can search through it a day. I ran out of my limit each time per day so it made things a bit difficult but over all, this was a fun experience to go through. I have several other automation that I set up in my server but this is the first time I was able to incorperate Splunk and my PFSense firewall. If you are interested in the full code to my script, please click below to view it.





