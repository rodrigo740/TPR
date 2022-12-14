from irc_class import *
import os
import random
import time

## IRC Config
server = "127.0.0.1" # Provide a valid server IP/Hostname
port = 6697
channel = "#python"
botnick = "sender"
botnickpass = "botpass"
botpass = "<%= @botpass %>"
irc = IRC()
irc.connect(server, port, channel, botnick, botpass, botnickpass)

while True:
    text = irc.get_response()
    print(text)

    print("Command to send: ")
    cmd = input()
    if cmd != "":
        irc.send(channel, cmd)
        print(cmd)
    #time.sleep(1)
        