# AidenSocks


## Intro

AidenSocks is a lightweight secured proxy, it's written by pure c.

Current version: 1.0.1

## Features

    as-server: AidenSocks Server.

    as-genkey: Generate the secret key.

    as-red   : Forwarding the tcp/udp for iptables, udp need TPROXY.

    as-socks5: Local socks5 server.

    as-dns   : Local dns server.

## Dependencies
* libiniparser
* openssl

## Usage

    as-[server|red|socks5|dns] INI_FILE
