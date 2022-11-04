import miniirc
import concurrent.futures



irc = miniirc.IRC('127.0.0.1', 6667, 'my-bot', ['#python'], ns_identity=('bot', 'bot2'), executor=concurrent.futures.ThreadPoolExecutor())