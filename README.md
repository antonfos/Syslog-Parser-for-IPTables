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

db.iptables.aggregate([{$group: {_id: "$src",  "total": {$sum : 1} , "ports": {"$addToSet": "$dpt"} } },{$sort: {"total": -1}} ])

{ "_id" : "116.31.116.33", "total" : 1651, "ports" : [ "22" ] }
{ "_id" : "58.218.198.146", "total" : 971, "ports" : [ "22" ] }
{ "_id" : "112.217.150.112", "total" : 113, "ports" : [ "22" ] }
{ "_id" : "185.165.123.76", "total" : 36, "ports" : [ "33563", "44337", "34020", "34951", "63468", "36874", "37497", "36889", "55874", "64434", "49881", "39947", "44920", "46164", "63345", "39996", "61986", "33549", "43186", "44490", "37376", "54889", "34482", "56508", "43479", "45071", "37008", "64452", "48106", "37245", "64324", "61911", "60351", "35093", "50051", "59938" ] }
{ "_id" : "178.63.11.129", "total" : 28, "ports" : [ "68" ] }
{ "_id" : "46.165.197.141", "total" : 18, "ports" : [ "80" ] }
{ "_id" : "212.139.123.104", "total" : 13, "ports" : [ "38889", "80", "22", "7000", "5432" ] }
{ "_id" : "91.197.232.109", "total" : 12, "ports" : [ "22" ] }
{ "_id" : "127.0.0.1", "total" : 12, "ports" : [ "6379" ] }
{ "_id" : "178.63.11.151", "total" : 11, "ports" : [ "7778", "9502", "995", "5900", "32777", "49159", "587", "3306", "21", "139" ] }
{ "_id" : "87.98.166.194", "total" : 8, "ports" : [ "52960", "39963", "48009", "56083", "64296", "34357", "64677", "34800" ] }
{ "_id" : "91.200.12.65", "total" : 7, "ports" : [ "80" ] }
{ "_id" : "52.192.218.169", "total" : 7, "ports" : [ "59314", "35379", "41599" ] }
{ "_id" : "162.210.196.100", "total" : 6, "ports" : [ "80" ] }
{ "_id" : "217.182.132.135", "total" : 5, "ports" : [ "50597", "59924", "48855", "46284", "40948" ] }
{ "_id" : "5.196.83.88", "total" : 5, "ports" : [ "54988", "39955", "51874", "59962", "61284" ] }
{ "_id" : "222.186.61.176", "total" : 5, "ports" : [ "22" ] }
{ "_id" : "46.30.215.35", "total" : 5, "ports" : [ "52032", "50386", "39503", "62715", "62275" ] }
{ "_id" : "182.100.67.118", "total" : 5, "ports" : [ "22" ] }
{ "_id" : "194.149.64.19", "total" : 4, "ports" : [ "22" ] }

