import sys
# import ssl
import pprint
from pymongo import MongoClient
import re
import datetime
import time
import os.path

syslog = "/var/log/syslog"
client = MongoClient('127.0.0.1:27017')
db = client.firewall
iptables = db.iptables
history = db.history

# Het the year from the file
filetimestamp = time.ctime(os.path.getmtime(syslog))
ts1 = time.strptime(filetimestamp, "%a %b %d %H:%M:%S %Y")
year = ts1.tm_year

# Open the file
pfile = open(syslog,"r") 

# Read the database history collection and get the timestamp of the last record
# processed so that we do not duplicate records
def GetLastDate():
   try:
      temp = history.find({'file': syslog}, {'pto': 1}).limit(1).sort("_id", -1)
      td = None
      for c in temp:
         td = c['pto']
      return td
   except:
      e = sys.exc_info()[0]
      print "An Error occured in GetLastDate : %s" % e
      return None

# Set the last record timestamp in the history collection
def SetLastDate(dt):
   return history.update({"file": syslog},{'$set': {"pto": dt}}, upsert=True)

# Parse the date of the record into a timestamp
def GetRecordDate(r):
   month = getMonth(r[0])
   dts = r[1]+"-"+month+"-"+str(year)+" "+r[2]
   dt = time.strptime(dts , "%d-%m-%Y %H:%M:%S")
   return datetime.datetime(dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec)   

# Simple Month Conversion
# Not Really Needed
def getMonth(m):
   if(m == "Jan"):
     return "01"
   elif (m == "Feb"):
     return "02"
   elif (m == "Mar"):
     return "03"
   elif (m == "Apr"):
     return "04"
   elif (m == "May"):
     return "05"
   elif (m == "Jun"):
     return "06"
   elif (m == "Jul"):
     return "07"
   elif (m == "Aug"):
     return "08"
   elif (m == "Sep"):
     return "09"
   elif (m == "Oct"):
     return "10"
   elif (m == "Nov"):
     return "11"
   elif (m == "Dec"):
     return "12"
   else :
     return None

# Splits out the Rule Name and the Input Interface
def GetIN(r):
   res = []
   s = r.split("=")
   res.append(s[1])
   
   x = s[0].split(":")
   res.append(x[0])
   res.append(x[1])
   return res

def getValue(r):
   return r.split("=")

def run():

    last_date = GetLastDate()
    rc = 0
    ra = 0
    rdate = None
    # Loop through
    # Syslog
    for line in pfile:
      rc += 1
      line = line.rstrip()

      # Identify IPTable logs
      if re.search("IN", line) is not None and re.search("OUT", line) is not None:
        #Split the logs
        Request = line.split(' ')
        # Parse the timestamp of the record
        rdate = GetRecordDate(Request)

        # If the Timestamp is > last Record Date then process this record
        if last_date is None or rdate > last_date :
          # Validate that this record is no malformed and everything is where we expect it to be 
          if (re.search("IN", Request[6]) is None):
            continue

            ra += 1
            # Get IN and Rule
            x = GetIN(Request[6])
            r = 0
            rec = {}
            rec["rule"] = x[1]
            rec[x[2].lower()] = x[0]
            rec['date_action'] = rdate
            rec['created_at'] = datetime.datetime.now()
            # Loop through the rest of the fields and add them to the record
            for ar in Request :
              if (r > 6):
                tval = getValue(ar)
                #Deal with Blank entities
                if len(tval) == 1:
                  tval.append("")

                  rec[tval[0].lower()] = tval[1]
              r += 1
            # Insert the record    
            iptables.insert(rec)

    # Update the Last record timestamp
    SetLastDate(rdate)
    print "Processed %d records and used %d records" % (rc, ra)


run()
