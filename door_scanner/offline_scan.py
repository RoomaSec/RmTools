import requests
import csv
scanned_hash = []
headers = {
    'apikey': "你的API key"
}


def check_file(hash):
    url = "https://api.metadefender.com/v4/hash/" + hash
    response = requests.request("GET", url, headers=headers)
    if response.text.find("Infected") > 0:
        print("file info:", response.text)
        scanned_hash.append(hash)
        return True
    return False


csvfile = open('./shimcache.csv', 'r')
lines = csvfile.readlines()
for line in lines:
    # strip the first ","
    # 你得自己改一下位置可能不同的csv文件位置不一样
    filehash = line.split(",")[1]
    if filehash in scanned_hash or filehash == None or filehash == "":
        continue
    print("scan:", filehash)
    if check_file(filehash):
        print("Found virs: ", line)
