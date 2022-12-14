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


def printer(s, lock):
    with lock:
        print(s)

def send_cmd(name, lock):
    logging.info("Thread %s: starting", name)

    while True:
        printer("Command to send: ", lock)
        cmd = input()
        if cmd != "":
            irc.send(channel, cmd)
            printer(cmd, lock)

def get_res(name, lock):
    logging.info("Thread %s: starting", name)

    while True:
        text = irc.get_response()
        printer(text, lock)

def main():
    lock = threading.Lock()

    th1 = threading.Thread(target=get_res, args=(1, lock))
    th2 = threading.Thread(target=send_cmd, args=(1, lock))
    
    th1.start()
    th2.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        exit(1)
    
    th1.join()
    th2.join()

    """
    try:
        while True:
            text = irc.get_response()
            print(text)
            #time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Main    : all done")
        exit(1)   
    """ 

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")
    main()
