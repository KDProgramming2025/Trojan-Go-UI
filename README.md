# Trojan-Go-UI
A simple UI for the https://github.com/p4gefau1t/trojan-go

The API must be enabled in the Trojan-Go config.\
Also the SQL must be enabled in the Trojan-Go config.

Note: It doesn't have login mechanism, you'll have to add that through the Apache directory password or some other ways.

server.js is the backend, run it on nodejs

You should create a config.json in the same directory as server.js

Example `config.json`:
```
{
  "listen": {
    "host": "127.0.0.1",
    "port": 8080
  },

  "mysql": {
    "host": "127.0.0.1",
    "port": 3306,
    "database": "trojango",
    "user": "trojango",
    "password": "A_STRONG_PASSWORD"
  },

  "trojan_api": {
    "bin": "trojan-go",
    "addr": "127.0.0.1:10001"
  },

  "link": {
    "host": "example.com",
    "port": 443,
    "ws_path": "/whatever",
    "sni": "example.com",
    "ws_host": "example.com"
  }
}
```
In this config the `trojan_api` will be running on port 10001\
The `listen` block is for nodejs 

The above config is assuming you have trojan-go running on port 10000 and have such config for the apache webserver:
```
<VirtualHost example.com:443>
	ServerAdmin webmaster@localhost

	DocumentRoot /var/www/html


	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	SSLEngine on
    
	SSLCertificateFile      /root/cert.crt
	SSLCertificateKeyFile   /root/private_key.key
	
	ProxyPreserveHost On
  ProxyPass        "/whatever" "ws://127.0.0.1:10000/whatever"
  ProxyPassReverse "/whatever" "ws://127.0.0.1:10000/whatever"


	<FilesMatch "\.(?:cgi|shtml|phtml|php)$">
		SSLOptions +StdEnvVars
	</FilesMatch>
	<Directory /usr/lib/cgi-bin>
		SSLOptions +StdEnvVars
	</Directory>
</VirtualHost>

```

The traffic on `https://example.com/whatever` will be forwarded to `ws://127.0.0.1:10000/whatever` by Apache's proxy.\
Look up "Apache reverse proxy"

Example `/etc/trojan-go/config.json` for the above `server.js`'s `config.json`:
```
{
  "run_type": "server",
  "local_addr": "127.0.0.1",
  "local_port": 10000,

  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "disable_http_check": false,

  "password": [],

  "websocket": {
    "enabled": true,
    "path": "/whatever",
    "host": "example.com"
  },

  "transport_plugin": {
    "enabled": true,
    "type": "plaintext"
  },
  
  "mysql": {
    "enabled": true,
    "server_addr": "127.0.0.1",
    "server_port": 3306,
    "database": "trojango",
    "username": "trojango",
    "password": "A_STRONG_PASSWORD",
    "check_rate": 5
  },

  "log_level": 1,

  "api": {
    "enabled": true,
    "api_addr": "127.0.0.1",
    "api_port": 10001,
    "ssl": {
      "enabled": false,
      "cert": "",
      "key": "",
      "verify_client": false,
      "client_cert": []
    }
  }
}
```

