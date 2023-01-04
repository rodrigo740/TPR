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

### Launch Stunnel
Infected client connects to an external SSH server via a TLS tunnel.
Run on infected client:
```
$ stunnel stunnel-infected.conf
```
Run on attacker server:
```
$ stunnel stunnel-attacker.conf
```