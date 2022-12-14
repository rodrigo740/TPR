from irc_class import *
import os
import random
import time
import logging
import threading

## IRC Config
server = "127.0.0.1"
port = 6697
channel = "#tpr"
botnick = "sender"
botnickpass = "botpass"
botpass = "<%= @botpass %>"
irc = IRC()
irc.connect(server, port, channel, botnick, botpass, botnickpass)


def thread_function(name):
    logging.info("Thread %s: starting", name)

    while True:
        print("Command to send: ")
        cmd = input()
        if cmd != "":
            irc.send(channel, cmd)
            print(cmd)

def main():
    text = irc.get_response()
    print(text)

    x = threading.Thread(target=thread_function, args=(1,))
    x.start()
    
    try:
        while True:
            text = irc.get_response()
            print(text)
            #time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Main    : all done")
        exit(1)    

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")
    main()
