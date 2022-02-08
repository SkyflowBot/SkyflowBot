import os
import requests
from replit import db
from urlextract import URLExtract
from urllib.parse import urlparse
from discord import Embed, Color
import re2
import time

# declare variables
extractor = URLExtract()

vault_id = 'g8c7626cda044dc9bb02564202e54005'
Skyflow_base = 'https://ebfc9bee4242.vault.skyflowapis.com/v1/vaults/' + vault_id
headers = {"Authorization": "Bearer " + os.environ['Skyflow'], 'Content-Type': 'application/json'}

regex_list = [
        r"(?i)(ida:password|IssuerSecret|(api|client|app(lication)?)[_\-]\-?(key|secret)[^,a-z]|\.azuredatabricks\.net).{0,10}(dapi)?[a-z0-9/+]{22}",
        r"(?i)(x-api-(key|token).{0,10}[a-z0-9/+]{40}|v1\.[a-z0-9/+]{40}[^a-z0-9/+])",
        r"(?-i)\WAIza(?i)[a-z0-9_\\\-]{35}\W",
        r"(?i)(\Wsig\W|Secret(Value)?|IssuerSecret|(\Wsas|primary|secondary|management|Shared(Access(Policy)?)?).?Key|\.azure\-devices\.net|\.(core|servicebus|redis\.cache|accesscontrol|mediaservices)\.(windows\.net|chinacloudapi\.cn|cloudapi\.de|usgovcloudapi\.net)|New\-AzureRedisCache).{0,100}([a-z0-9/+]{43}=)",
        r"(?i)visualstudio\.com.{1,100}\W(?-i)[a-z2-7]{52}\W",
        r"(?i)se=2021.+sig=[a-z0-9%]{43,63}%3d",
        r"(?i)(x-functions-key|ApiKey|Code=|\.azurewebsites\.net/api/).{0,100}[a-z0-9/\+]{54}={2}",
        r"(?i)code=[a-z0-9%]{54,74}(%3d){2}",
        r"(?i)(userpwd|publishingpassword).{0,100}[a-z0-9/\+]{60}\W",
        r"(?i)[^a-z0-9/\+][a-z0-9/\+]{86}==",
        r"(?-i)\-{5}BEGIN( ([DR]SA|EC|OPENSSH|PGP))? PRIVATE KEY( BLOCK)?\-{5}",
        r"(?i)(app(lication)?|client)[_\-]?(key(url)?|secret)([\s=:>]{1,10}|[\s\"':=|>\]]{3,15}|[\"'=:\(]{2})[^\-]",
        r"(?i)refresh[_\-]?token([\s=:>]{1,10}|[\s\"':=|>\]]{3,15}|[\"'=:\(]{2})(\"data:text/plain,.+\"|[a-z0-9/+=_.-]{20,200})",
        r"(?i)AccessToken(Secret)?([\s\"':=|>\]]{3,15}|[\"'=:\(]{2}|[\s=:>]{1,10})[a-z0-9/+=_.-]{20,200}",
        r"(?i)[a-z0-9]{3,5}://[^%:\s\"'/][^:\s\"'/\$]+[^:\s\"'/\$%]:([^%\s\"'/][^@\s\"'/]{0,100}[^%\s\"'/])@[\$a-z0-9:\.\-_%\?=/]+",
        r"(?i)snmp(\-server)?\.exe.{0,100}(priv|community)",
        r"(?i)(ConvertTo\-?SecureString\s*((\(|\Wstring)\s*)?['\"]+)",
        r"(?i)(Consumer|api)[_\-]?(Secret|Key)([\s=:>]{1,10}|[\s\"':=|>,\]]{3,15}|[\"'=:\(]{2})[^\s]{5,}",
        r"(?i)authorization[,\[:= \"']+([dbaohmnsv])",
        r"(?i)-u\s+.{2,100}-p\s+[^\-/]",
        r"(?i)(amqp|ssh|(ht|f)tps?)://[^%:\s\"'/][^:\s\"'/\$]+[^:\s\"'/\$%]:([^%\s\"'/][^@\s\"'/]{0,100}[^%\s\"'/])@[\$a-z0-9:\.\-_%\?=/]+",
        r"(?i)(\Waws|amazon)?.{0,5}(secret|access.?key).{0,10}\W[a-z0-9/\+]{40}",
        r"(?-i)(eyJ0eXAiOiJKV1Qi|eyJhbGci)",
        r"(?i)@(\.(on)?)?microsoft\.com[ -~\s]{1,100}?(\w?pass\w?)",
        r"(?i)net(\.exe)?.{1,5}(user\s+|share\s+/user:|user-?secrets? set)\s+[a-z0-9]",
        r"(?i)xox[pbar]\-[a-z0-9]",
        r"(?i)[\":\s=]((x?corp|extranet(test)?|ntdev)(\.microsoft\.com)?|corp|redmond|europe|middleeast|northamerica|southpacific|southamerica|fareast|africa|exchange|extranet(test)?|partners|parttest|ntdev|ntwksta)\W.{0,100}(password|\Wpwd|\Wpass|\Wpw\W|userpass)",
        r"(?i)(sign_in|SharePointOnlineAuthenticatedContext|(User|Exchange)Credentials?|password)[ -~\s]{0,100}?@([a-z0-9.]+\.(on)?)?microsoft\.com['\"]?",
        r"(?i)(\.database\.azure\.com|\.database(\.secure)?\.windows\.net|\.cloudapp\.net|\.database\.usgovcloudapi\.net|\.database\.chinacloudapi\.cn|\.database.cloudapi.de).{0,100}(DB_PASS|(sql|service)?password|\Wpwd\W)",
        r"(?i)(secret(.?key)?|password)[\"']?\s*[:=]\s*[\"'][^\s]+?[\"']",
        r"(?i)[^a-z\$](DB_USER|user id|uid|(sql)?user(name)?|service\s?account)\s*[^\w\s,]([ -~\s]{2,120}?|[ -~]{2,30}?)([^a-z\s\$]|\s)\s*(DB_PASS|(sql|service)?password|pwd)",
        r"(?i)(password|secret(key)?)[ \t]*[=:]+[ \t]*([^:\s\"';,<]{2,200})",
    ]


async def analyzeAttachmentsAndUrls(client, message):
      # Process urls if any in the message
      isUrlAttach = False
      urls = extractor.find_urls(message.content)
      domain =""
      if urls:
        domain = urlparse(urls[0]).netloc
        if domain == 'cdn.discordapp.com':
          isUrlAttach = True
      print(urls)

      # processing attachments in message
      if (len(message.attachments) or len(urls)):
        attachmentUrl = ''
        if message.attachments:
          attachmentUrl = str(message.attachments[0].url)
        else:
          attachmentUrl = str(urls[0])
                    
        if(len(message.attachments) and message.attachments[0].filename.split(".")[-1] in db[str(message.guild.id)+"_extension_types"].value):
          await message.channel.send("Attached File has been deleted, as the file extension - ''"+ message.attachments[0].filename.split(".")[-1] + "'' has been marked as blacklisted by server admin.")
          await message.delete() # Delete the message for security purposes
        elif(isUrlAttach and attachmentUrl.split(".")[-1] in db[str(message.guild.id)+"_extension_types"].value):
          await message.channel.send("Attached File has been deleted, as the file extension - ''"+ attachmentUrl.split(".")[-1] + "'' has been marked as blacklisted by server admin.")
          await message.delete() # Delete the message for security purposes
        else:
          obj = {
            "records": [
              {
                "fields": {
                  "username": message.author.name,
                  "url": attachmentUrl,
                  "department": list(filter(lambda x: "Department" in x.name, message.author.roles))[0].name,
                  "channelid": str(message.channel.id)
                }
              }
            ],
            "tokenization": True
          }
          # Change hardcoded channel ID
          cha = client.get_channel(936924483581775872)
          resp = requests.post(Skyflow_base + "/table2", headers = headers, json = obj)
          # print(resp.json())
          e = Embed(color = Color.blurple(), title = 'Sensitive Data Detected',description='Attachment/URL detected')
          e.add_field(
            name = "Skyflow ID: \n",
            value = resp.json()["records"][0]["skyflow_id"]
          )
          e.add_field(
            name = "Tokenized Attachment/URL: \n",
            value = resp.json()["records"][0]["tokens"]["url"]
          )
          e.set_footer(text="Use $view Skyflow_ID to view more about the Data")
          await cha.send(embed=e)
          await message.delete()
          await message.channel.send("Sensitive Data Detected. Data should be verified by department or server admin.")
          return
      else:
        for i in regex_list:
          a = re2.search(i, message.content)
          if a:
            obj2 = {
            "records": [
              {
                "fields": {
                  "username": message.author.name,
                  "message":message.content,
                  "url": "",
                  "department": list(filter(lambda x: "Department" in x.name, message.author.roles))[0].name,
                  "channelid": str(message.channel.id)
                }
              }
            ],
            "tokenization": True
            }
            # Change hardcoded channel ID
            cha = client.get_channel(936924483581775872)
            resp = requests.post(Skyflow_base + "/table3", headers = headers, json = obj2)
            print(resp.json())
            e = Embed(color = Color.blurple(), title = 'Sensitive Data Detected',description='Password/Key/Secret detected')
            e.add_field(
              name = "Skyflow ID: \n",
              value = resp.json()["records"][0]["skyflow_id"]
            )
            e.add_field(
              name = "Tokenized Message Content: \n",
              value = resp.json()["records"][0]["tokens"]["message"]
            )
            e.set_footer(text="Use $view Skyflow_ID to view more about the Data")
            await cha.send(embed=e)
            await message.delete()
            await message.channel.send("Sensitive Data Detected. Data should be verified by department or server admin.")
          # print(i)

async def analyzeMessage(client, message):
  msg = message.content
  
  if message.author.guild_permissions.administrator and msg.startswith("$extensionTypes"):
    data = msg.split()[1:]
    # print(data)
    try:
      [db[str(message.guild.id)+"_extension_types"].append(i) for i in data]
    except:
      db[str(message.guild.id)+"_extension_types"] = []
      [db[str(message.guild.id)+"_extension_types"].append(i) for i in data]
    # db[str(message.guild.id)+"_extension_types"] = data
    # print(db[str(message.guild.id)+"_extension_types"])
    await message.channel.send("extension types successfully stored")
    await message.delete() # Delete the message for security purposes
    print("Stored allowable extension types")
  if message.channel.id == 936924483581775872: # private channel ID
    if msg.startswith("$view"):
      data = msg.split()[1:][0]
      table = '/table2/'
      try:
        resp = requests.get(Skyflow_base + table  + data + '?redaction=DEFAULT', headers = headers).json()["fields"]
      except:
        table = '/table3/'
        resp = requests.get(Skyflow_base + table + data + '?redaction=DEFAULT', headers = headers).json()["fields"]
      url_token = requests.get(Skyflow_base + table + data + '?tokenization=true', headers = headers).json()["fields"]
      resp3 = ''
      if resp["department"] in [i.name for i in message.author.roles]:
        user = client.get_user(int(message.author.id))
        resp3 = requests.get(Skyflow_base + table + data + '?redaction=PLAIN_TEXT', headers = headers).json()["fields"]
      e = Embed(color = Color.blurple(), title = 'Sensitive Data Information',description='View more information with sensitive data tokenized. Department Admin would be DMed sensitive information.')
      e.add_field(
        name = "Username: \n",
        value = resp["username"]
      )
      e.add_field(
        name = "Channel ID: \n",
        value = resp["channelid"]
      )
      e.add_field(
        name = "Department: \n",
        value = resp["department"]
      )
      if table == '/table2/':
        if resp3:
          e.add_field(
            name = "URL: \n",
            value = resp3["url"]
          )
        else:
          e.add_field(
            name = "URL: \n",
            value = resp["url"]
          )
        e.add_field(
          name = "URL token: \n",
          value = url_token["url"]
        )
        e.set_footer(text="Use $scan URL_token to view more about the Data")
      else:
        if resp3:
          e.add_field(
            name = "Message Content: \n",
            value = resp3["message"]
          )
        else:
          e.add_field(
            name = "Message Content: \n",
            value = resp["message"]
          )
        e.add_field(
          name = "Message Token: \n",
          value = url_token["message"]
        )
      if resp3:
        await user.send(embed=e)
        return
      else:
        await message.channel.send(embed=e)
        return
    elif msg.startswith("$scan"):
      data2 = msg.split()[1:][0]
      headers2 = {"X-Skyflow-Authorization" :os.environ['Connection_Skyflow'],"x-apikey":"95918b21aecb95299e659631441f36edb959c320f2acd62c2db09e6e5b3e9c74", 'Content-Type': 'application/x-www-form-urlencoded', 'Accept':'application/json'}
      resp = requests.post('https://ebfc9bee4242.gateway.skyflowapis.com/v1/gateway/outboundRoutes/b5d66ebfe56b4f22b619a05dce438106/urls', headers = headers2, data='url='+data2)

      time.sleep(1.5)

      id = resp.json()["data"]["id"]
      url = "https://www.virustotal.com/api/v3/analyses/" + id
      
      headers3 = {
          "Accept": "application/json",
          "x-apikey": "95918b21aecb95299e659631441f36edb959c320f2acd62c2db09e6e5b3e9c74"
      }
      resp2 = requests.get(url, headers = headers3).json()["data"]["attributes"]["stats"]
      e = Embed(color = Color.blurple(), title = 'VirusTotal Report',description='Malware Detection results based on various websites through VirusTotal')
      e.add_field(
        name = "Attachment/URL Token: \n",
        value = data2,
        inline = False
      )
      e.add_field(
        name = "Harmless: \n",
        value = resp2["harmless"]
      )
      e.add_field(
        name = "Malicious: \n",
        value = resp2["malicious"]
      )
      e.add_field(
        name = "Suspicious: \n",
        value = resp2["suspicious"]
      )
      e.add_field(
        name = "Undetected: \n",
        value = resp2["undetected"]
      )
      e.add_field(
        name = "Timeout: \n",
        value = resp2["timeout"]
      )
      e.set_footer(text="Use $approve Skyflow_ID if data is safe.")
      await message.channel.send(embed=e)
      # print(resp2.json()["data"]["attributes"]["stats"])
      return
    elif msg.startswith("$approve"):
      data = msg.split()[1:][0]
      table = '/table2/'
      try:
        resp = requests.get(Skyflow_base + "/table2/" + data + '?redaction=PLAIN_TEXT', headers = headers).json()["fields"]
      except:
        table = '/table3/'
        resp = requests.get(Skyflow_base + table + data + '?redaction=PLAIN_TEXT', headers = headers).json()["fields"]
      if resp["department"] in [i.name for i in message.author.roles]:
        requests.delete(Skyflow_base + table + data, headers = headers)
        cha = client.get_channel(int(resp["channelid"]))
        e = Embed(color = Color.blurple(), title = 'Verified Sensitive Data',description='Safe Data approved by department admin.')
        e.add_field(
          name = "Shared by: \n",
          value = resp["username"]
        )
        if table == '/table2/':
          e.add_field(
            name = "Tokenized Attachemt/URL: \n",
            value = resp["url"],
            inline = False
          )
        else:
          e.add_field(
            name = "Tokenized Message Content: \n",
            value = resp["message"]
          )
        await cha.send(embed=e)
        return
      else:
        await message.channel.send("Not Authorized to approve. Only Department Admin can approve.")

  # process messages for non-admin user
  await analyzeAttachmentsAndUrls(client, message)