import configparser
import requests,os
import json
import pycountry
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import warnings
import pandas as pd
import sendMail

warnings.filterwarnings("ignore")
config = configparser.ConfigParser()
config.read('config.ini')

VirusTotal_API = config["API's"]["VirusTotal_API"]
AbuseIPDB_API = config["API's"]["AbuseIPDB_API"]
DB_Password = config["API's"]["DB_Password"]
IPs = ["103.67.79.165","196.251.87.74","218.92.0.220"]

AbuseIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
VirusTotal_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

uri = f"mongodb+srv://bharathj0410:{DB_Password}@mycluster.nfahr.mongodb.net/?appName=MyCluster"
client = MongoClient(uri, server_api=ServerApi('1'))

def get_country_name(Country_Code):
    try:
        Country_Name = pycountry.countries.get(alpha_2=Country_Code.upper()).name
        # Country_Flag = "".join([chr(0x1F1E6 + ord(c) - ord('A')) for c in Country_Code.upper()])
        return [Country_Name,Country_Code]
    except Exception as e:
        return str(e)

def insert_database(data):
    try:
        client.admin.command('ping')
        db = client["IOC_Enrichment"]
        collection = db["AbuseVT"]

        inserted_id = collection.insert_one(data).inserted_id
        if(inserted_id):
            print("Data Inserted Successfully")
    except Exception as e:
        print(e)

for IP in IPs:  
    AbuseIPDB_Response = requests.get(
        url=AbuseIPDB_URL, 
        headers={'Accept': 'application/json','Key': AbuseIPDB_API},
        params={'ipAddress': IP},verify=False
    )
    AbuseIPDB_data = json.loads(AbuseIPDB_Response.text)["data"]

    if(AbuseIPDB_data["abuseConfidenceScore"]>=97):
        excel_file = "AbuseIPDB_Result.xlsx"
        if os.path.exists(excel_file):
            existing_df = pd.read_excel(excel_file)
            df = pd.read_json(json.dumps([AbuseIPDB_data]))
            df = pd.concat([existing_df, df], ignore_index=True)
            df.to_excel(excel_file, index=False)
        else:
            pd.read_json(json.dumps([AbuseIPDB_data])).to_excel("AbuseIPDB_Result.xlsx",index=False)

VirusTotal_Response = requests.get(
    VirusTotal_URL+IPs[0], 
    headers={"accept": "application/json","x-apikey": VirusTotal_API}
)
VirusTotal_data = json.loads(VirusTotal_Response.text)["data"]

IPData = {}
IPData["IP"] = VirusTotal_data["id"]
Country_Code = VirusTotal_data["attributes"]["country"]
getCountry = get_country_name(Country_Code)
IPData["Country Flag"] = f"""<img src="https://flagcdn.com/w40/{str(getCountry[1]).lower()}.png" alt="Flag">"""
IPData["Country Code"] = VirusTotal_data["attributes"]["country"]
IPData["Country Name"] = getCountry[0]
IPData["Malicious"] = VirusTotal_data["attributes"]["last_analysis_stats"]["malicious"]
IPData["Harmless"] = VirusTotal_data["attributes"]["last_analysis_stats"]["harmless"]
IPData["UnDetected"] = VirusTotal_data["attributes"]["last_analysis_stats"]["undetected"]
IPData["Suspicious"] = VirusTotal_data["attributes"]["last_analysis_stats"]["suspicious"]

# The urls relationship returns a list of the IP's URLs. This relationship is only available for Premium API users. Hence Taking sample data
URLData = {}
with open("url_sample.json") as file:
    data = json.load(file)["data"][0]["attributes"]
    url_sample = data["last_analysis_stats"]
# URLData["Detected URLs"] = data["url"]
URLData["Detected URLs"] = "hxxp://www.foo.com/sorry"
URLData["UnDetected URLs"] = url_sample["undetected"]
URLData["Detected_URLs"] = url_sample["harmless"]+url_sample["malicious"]+url_sample["suspicious"]+url_sample["timeout"]
URLData["Malicious"] = url_sample["malicious"]
URLData["Harmless"] = url_sample["harmless"]
URLData["timeout"] = url_sample["timeout"]
URLData["Suspicious"] = url_sample["suspicious"]

# The downloaded_files relationship returns a list of files that were available from an URL under the given IP address at some moment. This relationship is only available for Premium API users. Hence Taking sample data
FileData = {}
with open("downloaded_files_sample.json") as file:
    data = json.load(file)["data"][0]["attributes"]
    file_sample = data["last_analysis_stats"]
    file_sample_names = data["names"]
FileData["File Names"] = file_sample_names
FileData["UnDetected Downloaded Samples"] = file_sample["undetected"]
FileData["Detected Downloaded Samples"] = file_sample["failure"]+file_sample["harmless"]+file_sample["malicious"]+file_sample["suspicious"]+file_sample["timeout"]+file_sample["type-unsupported"]
FileData["Malicious"] = file_sample["malicious"]
FileData["Harmless"] = file_sample["harmless"]
FileData["Timeout"] = file_sample["timeout"]
FileData["Suspicious"] = file_sample["suspicious"]
FileData["Failures"] = file_sample["failure"]


IP_Table = pd.read_json(json.dumps([IPData])).to_html(escape=False,index=False).replace('class="dataframe"','style="border-collapse: collapse"')
URL_Table = pd.read_json(json.dumps([URLData])).to_html(escape=False,index=False).replace('class="dataframe"','style="border-collapse: collapse"')
File_Table = pd.read_json(json.dumps([FileData])).to_html(escape=False,index=False).replace('class="dataframe"','style="border-collapse: collapse"')

MainData = {"IP Data": IPData, "URL Data":URLData,"File Data":FileData}

insert_database(MainData)

recipient_email = ""
cc_email = ""
subject = "Automated IP Enrichment Report – By Bharath"
html_body = ""
with open("Email_Template.htm") as file:
    html_body = file.read()
    html_body = html_body.replace("IP_Address",IPs[0]).replace("IP_Data",IP_Table).replace("URL_Data",URL_Table).replace("File_Data",File_Table)
attachment = os.path.abspath("AbuseIPDB_Result.xlsx")
sendMail.send_outlook_email(recipient_email, cc_email, subject, html_body, attachment)
