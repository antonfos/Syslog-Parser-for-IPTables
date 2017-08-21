# Syslog-Parser-for-IPTables
Parses IPTables entries out of Syslog and writes them to a MongoDB Database for Analysis.

Currently the program reads the file /var/log/syslog
Creates a dataabase called firewall

Some Aggrigation queries

db.iptables.aggregate([{$group: {_id: "$dpt",  "total": {$sum : 1} }},{$sort: {"total": -1}} ])

{ "_id" : "22", "total" : 3043 }
{ "_id" : "80", "total" : 42 }
{ "_id" : "68", "total" : 28 }
{ "_id" : "6379", "total" : 12 }
{ "_id" : "5432", "total" : 6 }
{ "_id" : "445", "total" : 5 }
{ "_id" : "7000", "total" : 4 }
{ "_id" : "48042", "total" : 4 }
{ "_id" : "42436", "total" : 4 }
{ "_id" : "59314", "total" : 3 }
{ "_id" : "41599", "total" : 3 }
{ "_id" : null, "total" : 2 }
{ "_id" : "38889", "total" : 2 }
{ "_id" : "33494", "total" : 1 }
{ "_id" : "44612", "total" : 1 }
{ "_id" : "48106", "total" : 1 }
{ "_id" : "59559", "total" : 1 }
{ "_id" : "54167", "total" : 1 }
{ "_id" : "47591", "total" : 1 }
{ "_id" : "48855", "total" : 1 }

 db.iptables.aggregate([{$match: {"dpt": "22"}},{$group: {_id: "$src",  "total": {$sum : 1} }},{$sort: {"total": -1}} ])
 
{ "_id" : "116.31.116.33", "total" : 1651 }
{ "_id" : "58.218.198.146", "total" : 971 }
{ "_id" : "112.217.150.112", "total" : 113 }
{ "_id" : "91.197.232.109", "total" : 12 }
{ "_id" : "222.186.61.176", "total" : 5 }
{ "_id" : "192.95.62.214", "total" : 4 }
{ "_id" : "194.149.64.19", "total" : 4 }
{ "_id" : "163.5.245.202", "total" : 4 }
{ "_id" : "211.110.184.22", "total" : 4 }
{ "_id" : "179.221.84.171", "total" : 4 }
{ "_id" : "58.218.205.102", "total" : 4 }
{ "_id" : "182.100.67.118", "total" : 4 }
{ "_id" : "152.249.249.216", "total" : 4 }
{ "_id" : "69.165.202.216", "total" : 4 }
{ "_id" : "104.193.253.47", "total" : 4 }
