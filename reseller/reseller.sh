#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » Gemilangkinasih࿐
# Email      » gemilangkinasih@gmail.com
# telegram   » https://t.me/gemilangkinasih
# whatsapp   » wa.me/+628984880039
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Gemilangkinasih࿐cd /root

cd /root
rm -r /usr/local/sbin/*
wget https://raw.githubusercontent.com/sanzzxx/sogokpetek/main/reseller/reseller.zip
unzip reseller.zip
chmod +x reseller/*
mv reseller/* /usr/local/sbin
rm -rf reseller
rm -rf reseller.zip
rm -rf reseller.sh
mkdir -p /etc/harga/
mkdir -p /etc/seller/
mkdir -p /etc/limit
wget -q -O /usr/bin/sogokpetek "https://raw.githubusercontent.com/sanzzxx/sogokpetek/main/reseller/sogokpetek" > /dev/null 2>&1
chmod +x /usr/bin/sogokpetek
echo "Fitur Reseller Success! Back In 5 Seconds"
sleep 5
menu