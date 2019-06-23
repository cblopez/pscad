#!/bin/bash

APT_GET_CMD=$(which apt-get)
APTITUDE_CMD=$(which aptitude)
YUM_CMD=$(which yum)
DNF_YUM_CMD=$(which dnf)
PACMAN_CMD=$(which pacman)
BREW_CMD=$(which brew)


if [[ ! -z $APT_GET_CMD ]]; then
	apt-get install nmap pip
elif [[ ! -z $APTITUDE_CMD ]]; then
	aptitude install nmap pip
elif [[ ! -z $YUM_CMD ]]; then
	yum install nmap pip
elif [[ ! -z $DNF_YUM_CMD ]]; then
	dnf install nmap pip
elif [[ ! -z $PACMAN_CMD ]]; then
	pacman -S nmap pip
elif [[ ! -z $BREW_CMD ]]; then
	brew install nmap pip
else
	echo "Unhandled Package Manager. Please install manually."
	exit 1;
fi


pip install --upgrade pip

pip install netifaces
pip install python-nmap
pip install scapy
pip install configparser
pip install reportlab
