import psycopg2
import pandas as pd


class UpdateSqlCounters:


  def __init__(self):

      # self.listSqlCounters = [["aaa",2,2023,120],["bbb",45,2023,120],["ccc",300,2023,120],["eee",150,2023,120]]
      self.listSqlCounters = []

      #Access to PostGreSQL
      self.postgres_connect = None
      self.cursor = None

      # self.sqlpreds = pd.DataFrame()
      self.counters_df = pd.DataFrame()
      self.preds_df = pd.DataFrame()

  def posGresPrep(self):
        self.open_PosGres()
        self.cursor = self.postgres_connect.cursor()
        print ( self.postgres_connect.get_dsn_parameters(),"\n")
        self.cursor.execute("SELECT version();")
        record = self.cursor.fetchone()
        print("You are connected to - ", record,"\n")

        postgres_currentSQLs_query = """ SELECT * FROM currentsqls"""
        self.cursor.execute(postgres_currentSQLs_query)
        self.sql_records = self.cursor.fetchall()

              # ---- Get the current cumul

        # cur.execute("SELECT * FROM function_name( %s,%s); ",(value1,value2))
        # sqlCounters = self.p1.cursor.execute("SELECT * FROM sqlcounters")
        self.cursor.execute("SELECT * FROM sqlcounters")
        sql_counters = self.cursor.fetchall()
        # print(" Total records " , sql_counters)
        # exit(0)

        self.counters_df = pd.DataFrame(sql_counters,columns=['hash','year','dayofyear','extract'])
        # print ('counters_df' , self.counters_df)


        # ---- Get the current preds
        self.cursor.execute("SELECT * FROM currentpreds")
        sql_preds = self.cursor.fetchall()
        # print(" Preds " , sql_preds)
        # print(" type of Preds " , type(sql_preds))

        self.preds_df = pd.DataFrame(sql_preds,columns=['hash','year','dayofyear','predstype','preds','preds_interval','anomaly','excessqty'])
        # print ('preds_df' , self.preds_df)

  # Closing PostGreSQL
  def close_PosGres(self):
     self.postgres_connect.close()

  # Opening PostGreSQL
  def open_PosGres(self):

     try:
         self.postgres_connect = psycopg2.connect(user = "context22",
                                  port = "5432",
                                  database = "context22"
                                  )
     except (Exception, psycopg2.Error) as error :
         print("Error while connecting to PostgreSQL", error)
         print ("Hello")

  def write_PosGres(self):
        print (" In write_PosGres    : ", self.listSqlCounters )
        # postgres_counterSQLs_query = """INSERT INTO sqlcounters (hash, year, dayofyear, extract) VALUES(%s,%s,%s,%s) ON CONFLICT (hash, year, dayofyear) DO UPDATE SET extract = EXCLUDED.extract + %s;"""
        postgres_counterSQLs_query = """INSERT INTO sqlcounters (hash, year, dayofyear, extract) VALUES(%s,%s,%s,%s) ON CONFLICT (hash, year, dayofyear) DO UPDATE SET extract = sqlcounters.extract + %s;"""
        for sqlcounter in self.listSqlCounters :
            hashVal = sqlcounter[0]
            yearVal = sqlcounter[2]
            dayofyearVal = sqlcounter[3]
            extractionVal = sqlcounter[1]

            self.cursor.execute(postgres_counterSQLs_query, (hashVal, yearVal, dayofyearVal , extractionVal , extractionVal))
            try :
               self.postgres_connect.commit()
            except:
               pass


  def updatePred4Anomaly(self,newSQL) :
        # postgres_currentpreds_query = """update currentpreds SET anomaly = true where hash='968c3ede97d8466333059c677f187f88' and year=2022 and dayofyear=104 and predstype='HWES3_MUL';"""
        postgres_currentpreds_query = """update currentpreds SET anomaly = true where hash=%s and year=%s and dayofyear=%s and predstype='HWES3_MUL';"""
        self.cursor.execute(postgres_currentpreds_query,(newSQL[0],newSQL[2],newSQL[3]))

        try :
           self.postgres_connect.commit()
           print (" Writing in PosGres 4 Anomaly Done" )
        except Exception as e:
           print ("PostGreSQL Error :", e)



  def updateCounter(self,newSQL) :
     flagFound = False

     for sqlCounter in self.listSqlCounters :
         # print (sqlCounter)
         if sqlCounter[0] == newSQL[0]:
            sqlCounter[1] = sqlCounter[1] + newSQL[1]
            latestCount = sqlCounter[1]
            flagFound = True

     if flagFound == False :
         self.listSqlCounters.append(newSQL)
         latestCount = newSQL[1]

     # -- Find the corresponding pred and check
     # newdf = df[(df.origin == "JFK") & (df.carrier == "B6")]     
     predFoundDf = self.preds_df[(self.preds_df.hash == newSQL[0]) & (self.preds_df.year == newSQL[2])& (self.preds_df.dayofyear == newSQL[3]) & (self.preds_df.predstype == 'HWES3_MUL')]     
     # print("Found the preds " , type(predFoundDf ))
     # print("Found the preds " , predFoundDf)

     # print(type(latestCount),latestCount)

     # --- Getting the pred value and computing the maxThreshold
     if predFoundDf.empty == False :
        # print ("in Pred Check against actual")
        preds =  predFoundDf['preds']
        # print(preds)
        preds_interval  =  predFoundDf['preds_interval']
        # print(preds_interval)
        # maxThreshold =  preds[1] + preds_interval[1]
        maxThreshold =  preds.values + preds_interval.values
        # if latestCount >= predFoundDf['preds'] + predFoundDf['preds_interval']:
        # print (latestCount ,  maxThreshold )

        # ---- retrieving the current amounf extractions
        counterFoundDf = self.counters_df[(self.counters_df.hash == newSQL[0]) & (self.counters_df.year == newSQL[2])& (self.counters_df.dayofyear == newSQL[3])]     
        if counterFoundDf.empty == False :
           extract = counterFoundDf['extract']
           # print (type(extract), " --- ", extract)
           # totalLatestCount = extract[0] + latestCount
           totalLatestCount = extract.values + latestCount
           # print ("Total in progress " , totalLatestCount)

           if totalLatestCount >= maxThreshold :
             print (" Excessive extraction in progress ")
             print (" current SQL " , newSQL )
             print (" Threshold = " , maxThreshold )
             self.updatePred4Anomaly(newSQL)
             return (newSQL , maxThreshold )

     return (0,0)
