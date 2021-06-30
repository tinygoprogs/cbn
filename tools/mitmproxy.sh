#!/bin/bash
if ! which mitmproxy; then
  echo missing mitmproxy
  exit 1
fi
mitmproxy --mode socks5 -v -p 1080
