import json
# Requests lib installation: 'pip install requests'
# PyJWT lib installation: 
# 'pip install pyjwt[crypto]>=2.0.0' or 
# 'pip install cryptography; pip install pyjwt>=2.0.0'
import jwt
import requests 
import time


def getSignedJWT(credsFile):
   # credsFile is the filepath to your credentials.json file
   # Load the credentials.json file into an object called creds
   fd = open(credsFile)
   creds = json.load(fd)
   fd.close()
   
   # Create the claims object with the data in the creds object
   claims = {
       "iss": creds["clientID"],
       "key": creds["keyID"], 
       "aud": creds["tokenURI"], 
       "exp": int(time.time()) + (3600), # JWT expires in Now + 60 minutes
       "sub": creds["clientID"], 
   }
   # Sign the claims object with the private key contained in the creds object
   signedJWT = jwt.encode(claims, creds["privateKey"], algorithm='RS256') 
   return signedJWT, creds  


def getBearerToken(signedJWT, creds):
   # Request body parameters
   body = {
       'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
       'assertion': signedJWT,
   }
   # Request URI (== https://api.skylfow.dev/v1/auth/sa/oauth/token) 
   tokenURI = creds["tokenURI"]
   
   # Send the POST request using your favorite Python HTTP request lib
   r = requests.post(tokenURI, json=body)
   return r.text


jwtToken, creds = getSignedJWT('./credentials.json')
bearerToken = getBearerToken(jwtToken, creds)
print(bearerToken)