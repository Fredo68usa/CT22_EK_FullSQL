from datetime import datetime
from elasticsearch import Elasticsearch, helpers

import csv
import urllib.parse
import json
import getpass
import datetime as dt
import time
import os
import hashlib
import calendar
import socket
import glob
import sys
import pdb

class EnrichFullSQLES:
  metadata_IP_Def ={
   '_id': 'afafafafafafafafafafafafaf',
   'Time Zone': 'None',
   'Owner': 'UnKnown',
   'Sub Env': 'UnKnown',
   'DB Type': 'UnKnown',
   'Retired': False,
   'IP': 'UnKnown',
   'Hostname': 'UnKnown',
   'Physical Type': 'UnKnown',
   'FQDN': 'UnKnown',
   'PII PHI': True,
   'Application': 'UnKnown',
   'Env': 'UnKnown',
   'Team': 'UnKnown',
   'Server Type': 'UnKnown',
   'Cluster': 'UnKnown',
   'Location': 'UnKnown'
}


  def __init__(self,param_json):

    # self.es = Elasticsearch()

    # self.process = psutil.Process(os.getpid())
    self.collector = str(sys.argv[1])

    with open(param_json) as f:
         self.param_data = json.load(f)

    self.path = self.param_data["path"]
    self.pathlength=len(self.path)
    self.pathProcessed = self.param_data["pathProcessed"]
    self.confidentialityPolicyRule = self.param_data["confidentialityPolicyRule"]
    self.datafileNotinserted=self.pathProcessed + "NotInserted"

    self.esServer = self.param_data["ESServer"]
    self.esUser = self.param_data["ESUser"]
    self.esPwd = self.param_data["ESPwd"]

    self.es = Elasticsearch([self.esServer], http_auth=(self.esUser, self.esPwd))

    self.index = self.param_data["index"]
    print('Number of arguments:', len(sys.argv), 'arguments.')
    print('Argument List:', str(sys.argv))

    self.InProg = self.path + 'FullSQL_Enrichment_In_Progress_'+ self.collector
    if os.path.exists(self.InProg) == True :
       print ('Process in Progress - Exiting')
       exit(0)
    else:
       os.system('touch ' + self.InProg)

    self.fullSQLMany=[]
    self.DAMDataRec=[]
    field_list=[]
    self.SonarGSource = None
    self.myListAuthConn = []

    self.myListIPs = []
    self.myListDBUsers = []
    self.myListSrcPrg = []
    self.myListSelectType = []
    self.myListCommands = []
    self.myListAuthConn = []



# --- Metadata  ----
  def MetaData(self):

    # ---- Get A_IPs
    A_IPs_tmp = self.es.search(index="a_ips", body={"query": {"match_all": {}}, "size": 10000})
    # print("Got %d Hits:" % A_IPs_tmp['hits']['total']['value'])
    # print ("Type : ", type(A_IPs_tmp))
    for hit in A_IPs_tmp['hits']['hits']:
        # print( hit["_source"])
        self.myListIPs.append( hit["_source"])

    # print(myListIPs)

    A_DB_USERS_tmp = self.es.search(index="a_db_users", body={"query": {"match_all": {}}, "size": 10000})
    # print("Got %d Hits:" % A_IPs_tmp['hits']['total']['value'])
    # print ("Type : ", type(A_IPs_tmp))
    for hit in A_DB_USERS_tmp['hits']['hits']:
        # print( hit["_source"])
        self.myListDBUsers.append( hit["_source"])

    # print(myListIPs)

    A_SEL_TYP_tmp = self.es.search(index="a_sel_typ", body={"query": {"match_all": {}}, "size": 10000})
    # print("Got %d Hits:" % A_IPs_tmp['hits']['total']['value'])
    # print ("Type : ", type(A_IPs_tmp))
    for hit in A_SEL_TYP_tmp['hits']['hits']:
        # print( hit["_source"])
        self.myListSelectType.append( hit["_source"])

    # print(myListIPs)


  def lookup_A_IPs(self,FQDN,IP,Hostname):
    # if FQDN != None:
    if FQDN != None and FQDN != 'Not in DNS':
       # print ("Youpi ...",FQDN)
       for i in range(0,len(self.myListIPs)):
           if 'FQDN' in self.myListIPs[i]:
               # fqdn_ref = myListIPs[i]['FQDN']
               if self.myListIPs[i]['FQDN'] == FQDN:
                   #print('Bingo',ip_ref)
                   return(self.myListIPs[i])

    if IP != None:
       for i in range(0,len(self.myListIPs)):
           if 'IP' in self.myListIPs[i]:
               # ip_ref = myListIPs[i]['IP']
               if self.myListIPs[i]['IP'] == IP:
                   #print('Bingo',ip_ref)
                   return(self.myListIPs[i])

    if Hostname != None :
       for i in range(0,len(self.myListIPs)):
           if 'Hostname' in self.myListIPs[i]:
               # host_ref = myListIPs[i]['Hostname']
               if self.myListIPs[i]['Hostname'] == Hostname:
                   #print('Bingo',ip_ref)
                   return(self.myListIPs[i])

    return (self.metadata_IP_Def)

  def lookup_A_SELECT(self,SEL_TYP):
    if SEL_TYP != None:
       # print ("Youpi ...",SRC_PRG)
       for i in range(0,len(self.myListSelectType)):

           if self.myListSelectType[i]['Select Type'] in SEL_TYP:
              return(self.myListSelectType[i])

  def lookup_A_DB_USER(self,DB_USER):
    if DB_USER != None:
       # print ("Youpi ...",SRC_PRG)
       for i in range(0,len(self.myListDBUsers)):

           if self.myListDBUsers[i]['DB User Name'] in DB_USER:
              return(self.myListDBUsers[i])

  # --- Enrich line with Metqadata
  def enrich_by_metadata(self,line):
    # print ('Enrich Metadata ')
    line = self.enrich_server(line)
    line = self.enrich_client(line)
    line = self.enrich_DB_User(line)
    line = self.enrich_Sel_Type(line)
    line = self.enrich_misc(line)
    line = self.confidence_level(line)
    return(line)

  def confidence_level(self,line):
    # print ("Client :" , line['Client Metadata']['Env'], "Server :" , line['Server Metadata']['Env'])
    if 'Env' in line['Client Metadata']:
       # print ("Client :" , line['Client Metadata']['Env'], "Server :" , line['Server Metadata']['Env'])
       if line['Client Metadata']['Env'] == line['Server Metadata']['Env']:
          line['Confidence Level'] = 20
       else:
           line['Confidence Level'] = -20
    else:
       line['Confidence Level'] = -20

    # print(line['Confidence Level'])
    return(line)

  def enrich_client(self,line):

    # --- Client
    if "Client Host Name" in line:
       Hostname = line['Client Host Name']
    else:
       Hostname = None

    try:
       line['Resolved Client Hostname']=socket.gethostbyaddr(line['Analyzed Client IP'])[0]
    except Exception as error:
       line['Resolved Client Hostname']="Not in DNS"

    if "Resolved Client Hostname" in line:
       FQDN = line['Resolved Client Hostname']
    else:
       FQDN = None

    if "Analyzed Client IP" in line:
       IP = line['Analyzed Client IP']
    else:
       IP = None

    server_metadata = self.lookup_A_IPs(FQDN,IP,Hostname)
    # pdb.set_trace()
    # print ("Client Metadata" , server_metadata )
    line["Client Metadata"] = server_metadata

    return(line)

  def enrich_DB_User(self,line):
      # --- DB User
    if "DB User Name" in line:
       DB_USER = line['DB User Name']
       DB_USER_t = DB_USER.split('\\')
       # print ('DB User Split ',DB_USER_t)
       if len(DB_USER_t) > 1:
          DB_USER_2 = DB_USER_t[0] + "&" + DB_USER_t[2]
       else:
          DB_USER_2 = DB_USER
    else:
       DB_USER = None

    db_user_metadata = self.lookup_A_DB_USER(DB_USER)
    line["DB User Metadata"] = db_user_metadata
    line["DB User Name 2"] = DB_USER_2

    return(line)

  def enrich_server(self,line):
    # --- Server
    if "Server Name" in line:
       Hostname = line['Server Host Name']
    else:
       Hostname = None

    try:
       line['Resolved Server Hostname']=socket.gethostbyaddr(line['Server IP'])[0]
    except Exception as error:
       line['Resolved Server Hostname']="Not in DNS"

    if "Resolved Server Hostname" in line:
       FQDN = line['Resolved Server Hostname']
    else:
       FQDN = None

    if "Server IP" in line:
       IP = line['Server IP']
    else:
       IP = None

    server_metadata = self.lookup_A_IPs(FQDN,IP,Hostname)
    line["Server Metadata"] = server_metadata
    # --- Return ---
    return(line)

  def enrich_Sel_Type(self,line):

    # --- Select Type
    if "Original SQL" in line:
       # print(len(line['Original SQL']))
       # line['Original SQL'] = line['Original SQL'][0:100]
       # SEL_TYP = line['Original SQL'][0:100]
       SEL_TYP = line['Original SQL']
       # SEL_TYP = line['Original SQL']
       # SEL_TYP = line['Original SQL']
    else:
       SEL_TYP = None

    # print("Select Type " , SEL_TYP)
    sel_metadata = self.lookup_A_SELECT(SEL_TYP)
    # print('sel_metadata is None')
    if sel_metadata is None:
       line["Select Type"] = "Wild - No Restriction -"

    if sel_metadata != None:
       line["Select Type"] = sel_metadata["Comment"]

    if line["Select Type"] == "Not Peculiar":
       sel_metadata = self.lookup_A_SELECT(SEL_TYP.upper())
       line["Select Type"] = sel_metadata


    return(line)





  def enrich_misc(self, line_meta):
      # --- MD5
      y = line_meta["Original SQL"]
      result = hashlib.md5(y.encode()).hexdigest()
      line_meta['HashHash'] = result
      line_meta['HashHash User Datastore'] = result+":"+line_meta['DB User Name 2']+":"+line_meta['Server IP']+":"+line_meta['Service Name']+":"+line_meta['Database Name']
      # print(line_meta['HashHash User Datastore'])
      DayOfWeek=line_meta['Timestamp Local Time'].weekday()
      line_meta['DayOfWeek']=calendar.day_name[DayOfWeek]
      DayOfYear=line_meta['Timestamp Local Time'].timetuple().tm_yday
      line_meta['DayOfYear']=DayOfYear
      WeekOfYear=line_meta['Timestamp Local Time'].isocalendar()[1]
      line_meta['WeekOfYear']=WeekOfYear
      Year=line_meta['Timestamp Local Time'].year
      line_meta['Year']=Year

     #print(WeekOfYear)
      return (line_meta)

  def process_all_files(self,DataFiles):
    # --- Loop for each DAM data file
    for datafile in DataFiles:
        print('Will be Processing : ',datafile)
        os.system('printf "' + datafile[1] + '\n" >> ' + self.InProg )
        self.SonarGSource =  datafile[0]
        perfDict={}
        perfDict["Processed File"]=datafile
        perfDict["Ticks File Before"] = time.time()
        # -- MAIN PROCESSING
        self.fullSQLMany=[]
        doc_count=self.process_one_file(datafile)
        print("Nbr of Docs to be Inserted", doc_count)
        if doc_count > 0 :
           self.insert_many_Elastic()

        os.system('rm -f ' + self.InProg)

        self.rename_file(datafile)

  def rename_file(self,datafile):

      shortname=datafile[1][self.pathlength:]
      print ("Rename as processed" , shortname)
      os.rename(datafile[1],self.pathProcessed + shortname)

  # --- Process 1 File at a time
  def process_one_file(self,datafile):
        print ('Processing' , datafile)
        # --- Initialization
        doc_count=0
        self.fullSQLMany=[]
        self.DAMDataRec=[]
        with open(datafile[1]) as csv_file:
            try:
               csv_reader = csv.reader(csv_file, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
               for line in csv_reader:
                   doc_count += 1
                   # print (line)
                   self.DAMDataRec.append(line)
                   # self.fullSQLMany.append(self.thisDict)
            except Exception as error:
                print ("Bad File  :",datafile[1])
                print ("Rename as Bad 2 " , datafile[1])
                os.rename(datafile[1], datafile[1] + '.bad')
                # DAMDataRec.clear()
                print(error)

        self.DAMDataRec[0][0]="UTC Offset"
        self.field_list=self.DAMDataRec[0]

        # -- Process 1 Line at a Time
        for i in range(1,len(self.DAMDataRec)):
                line=self.DAMDataRec[i]
                self.process_one_line(line)


        return(len(self.fullSQLMany))


  def insert_many_Elastic(self):
      try:

           response = helpers.bulk(self.es,self.fullSQLMany, index='enriched_full_sql')
           print ("\nRESPONSE:", response)
      except Exception as e:
           print("\nERROR:", e)


  def process_one_line(self,line):
                # print (line)

         if len(line) != 29 :
                   # print ('Too Short',line.rstrip())
                   # print ('Too Short',len(line))
            return()
         # if line[1] != 'Policy Rule 1' :
         if line[1] != self.confidentialityPolicyRule :
            print ('Wrong Policy')
                   # print(line[1])
            return()

         lineDict={}
         lineDict['SonarG Source']=self.SonarGSource
         item_count = 0

         for item in self.field_list :
            key, values = self.field_list[item_count],line[item_count]
            lineDict[key] = values
            item_count = item_count + 1
         # print(lineDict)
         line_meta = self.enrich_one_line(lineDict)

         # line_meta_ES = { "doc" : line_meta }
         # self.fullSQLMany.append(line_meta_ES)
         self.fullSQLMany.append(line_meta)

  def enrich_one_line(self,lineDict):
      # --- Timestamp
      ts = lineDict['Timestamp']
      utc_h = int(lineDict["UTC Offset"])
      new_ts=dt.datetime.strptime(ts[:19],'%Y-%m-%dT%H:%M:%S')
      lineDict['Timestamp'] = new_ts + dt.timedelta(hours=abs(utc_h))
      lineDict['Timestamp Local Time'] = new_ts
      # --- Session Start ----
      ts = lineDict['Session Start']
      new_ts=dt.datetime.strptime(ts[:19],'%Y-%m-%dT%H:%M:%S')
      lineDict['Session Start'] = new_ts + dt.timedelta(hours=abs(utc_h))


      # -- Conversion into Integers -----
      lineDict['Records Affected']=int(lineDict['Records Affected'])
      lineDict['Response Time']=int(lineDict['Response Time'])

      # --- Enrichment of the Line as a Dctionary
      line_meta = self.enrich_by_metadata(lineDict)

      return (line_meta)

  def DataFile_List(self):
    DataFile=[]
    DataFiles=[]
    csvFiles=glob.glob(self.path + "*" + self.collector + "*FSQL*.csv")
    for file in csvFiles:
       if "FSQL" in file:
         COLL = file.split('_')[1]
         DataFile.append(COLL)
         DataFile.append(file)
         DataFiles.append(DataFile)
         DataFile=[]
    return (DataFiles)



  def mainProcess(self):
    print("Start Full SQL ES Enrichment")

    # ---- Constructor
    # p1 = EnrichFullSQLES("param_data.json")

    # ---- Get All Metadata
    self.MetaData()

    # ---- Get list of files
    DataFiles = self.DataFile_List()
    print ('Nbr of Files to Process : ' , len(DataFiles))
    if len(DataFiles) == 0 :
       print ("NO file to process for Coll : " , self.collector)
       os.system('rm -f ' + self.InProg)
       exit(0)

    # ---- Process ALL  file
    self.process_all_files(DataFiles)


    print("End of Full SQL ES Enrichment")

