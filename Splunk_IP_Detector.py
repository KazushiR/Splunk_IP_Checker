import splunklib.client as client
import splunklib.results as results
from dotenv import load_dotenv
import json, time, re,requests, smtplib, os

#changes directory to load the environmental variables. 
os.chdir("Change_directory")
load_dotenv()

#set if ip addresses as well as port number to log into the splunk management system
HOST = "127.0.0.1"
PORT = 8089
#environmental variables to log into the splunk management system
USERNAME = os.getenv("Splunk_Username")
PASSWORD = os.getenv("Splunk_Password")

#api key for Abuseipdb
AbuseIPDB_key = os.getenv("Abuse_Key")

#credentials to log into email system as well as send out email to the "Reciever"
reciever = os.getenv("Reciever_email")
sender = os.getenv("Sender_email")
password = os.getenv("Sender_Password")

print(USERNAME)
print(PASSWORD)

print(os.getcwd())

#This is a set up ip addresses that will be ingested into abuseIPDB to check if there are any potential malicious ip addresses
global_source =[]
global_dest = []

#checks to see if ip address is in the list so it won't duplicate the ip addresses in the message.
ip_list = []

def search_parametere(HOST, PORT, USERNAME, PASSWORD, global_source, global_dest):
    #uses the above definitions to connect to the splunk instance
    service = client.connect(host = HOST, port = PORT, autologin=True, username = USERNAME, password = PASSWORD, output="json")     
    #this is the search_query to look at the pfsense firewall and see if it can look through the index to find the ip addresses
    search_query = "search index=firewall_pfsense | fields_raw | head 10"
    job = service.jobs.create(search_query)
    while not job.is_done():
        #if the job is not done while querying the search, it will wait 2 seconds before re-doing the search
        print("Waiting for job to finish...")
        time.sleep(2)
    #The 'result() is calling on the job to put it into a json format
    result_stream = job.results(output_mode=  "json")
    #The result_stream puts the json format into a string and the 'json.loads() loads into a python object
    results_data = json.loads(result_stream.read())
    
    #The result iterates through the result_data
    for result in results_data["results"]:
        #gets the items from the '_raw' key from the json object
        raw_data = result["_raw"]

        #this is a regex that looks for only ip addresses in the _raw object of the json
        match = re.search(r"(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+)", raw_data)
        if match:
            #if there is a match, it converts it into a source_ip/dest_ip variable and appends to the list accordingly
            source_ip = match.group(1)
            dest_ip = match.group(2)
            global_source.append(source_ip)
            global_dest.append(dest_ip)

        else:
            #if there is nothing, it moves on to the next part
            print("No source and destination IPs found in raw data")
    return global_source, global_dest


def ip_lookup(reciever, sender, password, ip_list, global_dest, AbuseIPDB_key):
    #this is an environmental variable to send emails to the myself for reports.
    message = "Here is a list of information for potential Malicious IP Addresses from Splunk.\n\n"
    try:
        #this is to get a get request to the abuseipdb.
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
        "Accept": "application/json",
        "Key": f'{AbuseIPDB_key}'
    }
        #iterates through the IP addresses in the list gotten from 'search_parametere()' definition
        for ip_addr in global_dest:
            #part of the AbuseIPDB query request
            querystring = {
            "ipAddress": f"{ip_addr}",
            "maxAgeInDays": "90"
            }
            #gets the response and decodes it into a dictionary format.
            AbuseIPDB_Response = requests.request(method="GET", url = url, headers = headers, params = querystring)
            decodedResponse = json.loads(AbuseIPDB_Response.text)
            #stores the value into variables and appends it into the message format
            ip_address = f"Ip Address: {decodedResponse['data']['ipAddress']}\n\n"
            score_counter = f"Confidence Score: {decodedResponse['data']['abuseConfidenceScore']}\n\n"
            domain = f"Domain: {decodedResponse['data']['domain']}\n\n"
            last_reported = f"Last_Reported: {decodedResponse['data']['lastReportedAt']}\n\n"
            host_name = f"Host Name: {decodedResponse['data']['hostnames']}\n\n"
            total_reports = f"Total Number of Reports: {decodedResponse['data']['totalReports']}\n\n"
            full_message = (ip_address + score_counter + domain + last_reported + host_name + total_reports)
            print(decodedResponse['data']['abuseConfidenceScore'])
            #The if statement below checks to see if the ip address is not in the list. If it is, it skips it, otherwise it adds it to the list 
            #as a way to double check and make sure duplicates are not added in.
            if decodedResponse['data']['abuseConfidenceScore']  >= 85:
                if ip_addr not in ip_list:
                    ip_list.append(ip_addr)
                    message += full_message + "\n\n"
                else:
                    print(f"IP {ip_addr} has a low confidence score, skipping...")
                
            else:
                print(f"IP {ip_addr} has a low confidence score, skipping...")

        #once it is added, it then connects to the gmail account to send an email that a malicious IP is being communicated within the network.
        if len(message) > len( "Here is a list of information for potential Malicious IP Addresses from Splunk.\n\n"):
            with smtplib.SMTP("smtp.gmail.com", 587) as s:
                s.starttls()
                s.login(sender, password)
                s.sendmail(sender, reciever, message)
                s.quit()
                print("finished!")
        else:
            print("Nothing found so far")
    #The KeyError will skip the try statement if it hits the rate limit of AbuseAPI of 1000 requests per day.
    except KeyError:
        print("Looks like ABuseIPD hit the rate limit.")

#records the last time checked to start off
last_time_checked = int(time.time())

while True:
    time.sleep(1)
    search_parametere(HOST, PORT, USERNAME, PASSWORD, global_source, global_dest)
    global_source = list(set(global_source))
    current_time = int(time.time())
    #Since abuseIPDB has a rate limit of 1,000 reports a day, it will aggregate the global_dest/source list and run
    #it through the ip_lookup definition all at once before resetting the list 1 hour a day
    if current_time - last_time_checked >= 86400:
        print("5 seconds has passed")
        last_time_checked = current_time
        ip_lookup(sender,reciever, password, ip_list, global_dest, AbuseIPDB_key)
