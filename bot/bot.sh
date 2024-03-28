#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » Gemilangkinasih࿐
# Email      » gemilangkinasih@gmail.com
# telegram   » https://t.me/gemilangkinasih
# whatsapp   » wa.me/+628984880039
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Gemilangkinasih࿐

NC='\e[0m'
g="\033[1;92m"
r="\033[1;91m"

REPO="https://raw.githubusercontent.com/sanzzxx/sogokpetek/main/bot/"
NS=$( cat /etc/xray/dns )
PUB=$( cat /etc/slowdns/server.pub )
domain=$(cat /etc/xray/domain)

clear
cd /usr/bin
rm -fr xbot.sh
rm -fr /usr/bin/kyt
rm -fr /usr/bin/xbot.zip*
cd

# Install
apt update && apt upgrade
apt install python3 python3-pip git
cd /usr/bin
wget -q -O bot.zip "${REPO}bot.zip"
unzip bot.zip
mv bot/* /usr/bin
chmod +x /usr/bin/*
rm -rf bot.zip
clear
wget -q -O xbot.zip "${REPO}xbot.zip"
unzip xbot.zip
pip3 install -r kyt/requirements.txt

clear
echo -e ""
echo -e "▀▀█▀▀ ▒█▀▀▀ ▒█░░░ ▒█▀▀▀ ▒█▀▀█ ▒█▀▀▀█ ▀▀█▀▀\033[0m" 
echo -e "░▒█░░ ▒█▀▀▀ ▒█░░░ ▒█▀▀▀ ▒█▀▀▄ ▒█░░▒█ ░▒█░░\033[0m" 
echo -e "░▒█░░ ▒█▄▄▄ ▒█▄▄█ ▒█▄▄▄ ▒█▄▄█ ▒█▄▄▄█ ░▒█░░\033[0m"
echo -e "\e[33m──────────────────────────────────────────\033[0m"
echo "Pergi ke @BotFather dan type /newbot untuk membuat bot baru"
echo "Pergi ke @MissRose_bot dan type /id untuk mendapatkan ID telegram"
echo -e "\e[33m──────────────────────────────────────────\033[0m"
read -p "Input bot Token : " bottoken
read -p "Input admin ID  : " admin
echo -e "\e[33m──────────────────────────────────────────\033[0m"
echo -e BOT_TOKEN='"'$bottoken'"' >> /usr/bin/kyt/var.txt
echo -e ADMIN='"'$admin'"' >> /usr/bin/kyt/var.txt
echo -e DOMAIN='"'$domain'"' >> /usr/bin/kyt/var.txt
echo -e PUB='"'$PUB'"' >> /usr/bin/kyt/var.txt
echo -e HOST='"'$NS'"' >> /usr/bin/kyt/var.txt
clear

cat > /etc/systemd/system/xbot.service << END
[Unit]
Description=Simple kyt - @gemilangkinasih
After=network.target

[Service]
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/python3 -m kyt
Restart=always

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl start xbot
systemctl enable xbot
systemctl restart xbot
cd

# Status Service Bot
bot_service=$(systemctl status xbot | grep active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
if [[ $bot_service == "running" ]]; then 
   sts_bot="${g}[ON]${NC}"
else
   sts_bot="${r}[OFF]${NC}"
fi

rm -fr /usr/bin/bot.zip
rm -fr /usr/bin/xbot.zip
clear
echo -e "\e[33m──────────────────────────────────────────\033[0m"
echo -e "\E[40;1;37m     INFORMATION DATABASE BOT TELEGRAM    \E[0m"
echo -e "\e[33m──────────────────────────────────────────\033[0m"
echo -e "  Status Bot Telgram : $sts_bot"
echo -e ""
echo -e "  Token Bot  : $bottoken"
echo -e "  ID admin   : $admin"
echo -e "  Subdomain  : $domain"
echo -e "  NS Domain  : $NS"
echo -e "\e[33m──────────────────────────────────────────\033[0m"
echo -e ""
read -p "Press [ Enter ] to back on menu"
menu