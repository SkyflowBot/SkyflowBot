import os
import discord
from discord.ext import commands
intents = discord.Intents(messages=True, guilds=True, members=True)
from keepalive import keep_alive

import processMessage

# declare variables
bot = commands.Bot("$")
bot.remove_command('help')
log_type = 'MessageLogs'
auditLog_type = 'DiscordAuditLogs'
client = discord.Client(intents=intents)

# Discord client is active
@client.event
async def on_ready():
  print('We have logged in...')


# Log when a message is sent in discord
@client.event
async def on_message(message):
  
  def check(event):
    return event.target.id == bot.user.id

  # Do not log messages by this client bot    
  if message.author == client.user:
    return
  
  await processMessage.analyzeMessage(client, message)

keep_alive()
client.run(os.environ['Bot_secret'])