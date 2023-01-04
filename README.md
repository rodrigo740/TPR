# TPR
Repositorio do projeto da cadeira de TPR (Técnicas de Percepção de Redes)

### Run IRC Server
```
$ cd miniircd
$ ./miniircd --verbose --ssl-cert-file ../openssl/server.crt --ssl-key-file ../openssl/server.key
```

### Launch Bots
Both bots must be run in different terminals.
```
$ cd bots
$ python3 talker.py
$ python3 listener.py
```
