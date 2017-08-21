import sys
# import ssl
import pprint
from pymongo import MongoClient
import re
import datetime
import time
import os.path

host = 'mongodb://127.0.0.1:27017/'
cert = '/home/antonf/egitest.pem'
cacert = '/home/antonf/ca.pem'
syslog = "/var/log/syslog"

client = MongoClient('127.0.0.1:27017')
db = client.firewall
iptables = db.iptables
lastproc = db.history


filetimestamp = time.ctime(os.path.getmtime(syslog))
#print "last modified: " , filetimestamp

ts1 = time.strptime(filetimestamp, "%a %b %d %H:%M:%S %Y")

# print "ts1 ", ts1

#print "year : ", ts1.tm_year 
year = ts1.tm_year

pfile = open(syslog,"r") 

def GetLastDate():
   try:
      temp = lastproc.find({'file': syslog}, {'pto': 1}).limit(1).sort("_id", -1)
      td = None
      for c in temp:
         #print "Record ", c
         td = c['pto']
      return td
   except:
      e = sys.exc_info()[0]
      print "An Error occured in GetLastDate : %s" % e
      return None

def SetLastDate(dt):
   # return lastproc.insert({"file": syslog, "pto": dt})
   return lastproc.update({"file": syslog},{'$set': {"pto": dt}}, upsert=True)

def GetRecordDate(r):
   # print "Processing ", r[0], r[1], r[2]
   month = getMonth(r[0])
   day = r[1]
   # print "Month: %s-%s-%s %s" % (r[1], month, year, r[2]) 
   dts = r[1]+"-"+month+"-"+str(year)+" "+r[2]
   dt = time.strptime(dts , "%d-%m-%Y %H:%M:%S")
   # print "Time tupple " , dt
   return datetime.datetime(dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec)   

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

def GetIN(r):
   res = []
   s = r.split("=")
   res.append(s[1])
   
   x = s[0].split(":")
   res.append(x[0])
   res.append(x[1])
   return res

def GetOUT(r):
    s = r[7].split("=")
    return s[1]

def getValue(r):
   return r.split("=")

def run():

    last_date = GetLastDate()
    rc = 0
    ra = 0
    for line in pfile:
       rc += 1
       line = line.rstrip()
       if re.search("IN", line) is not None and re.search("OUT", line) is not None:
          Request = line.split(' ')
          #print "Processing line : ", Request
          rdate = GetRecordDate(Request)
	  if (last_date is None or rdate > last_date ):
             #print "Exclude Lime for Input ", re.search("IN", Request[6]), Request[6]
             if (re.search("IN", Request[6]) is None):
                 #print "Pass"
                 continue
             ra += 1
             x = GetIN(Request[6])
             r = 0
             rec = {}
	     rec["rule"] = x[1]
          
             rec[x[2].lower()] = x[0]
          
             rec['date_action'] = rdate
             rec['created_at'] = datetime.datetime.now()
             for ar in Request :
                if (r > 6):
                   tval = getValue(ar)

                   # print "TVAL : ", tval
                   if len(tval) == 1:
                      tval.append("")

                   rec[tval[0].lower()] = tval[1]
                r += 1
                 
             iptables.insert(rec)

    SetLastDate(rdate)
    print "Processed %d records and used %d records" % (rc, ra)


run()
