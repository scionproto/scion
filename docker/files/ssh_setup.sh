#!/bin/bash
set -ex

# SSH daemon setup
adduser --disabled-password --gecos "" sshd
mkdir /etc/ssh/sshd_config
mkdir /run/sshd
ssh-keygen -t rsa -N "" -C "host-key" -f /etc/ssh/ssh_host_rsa_key
cp /share/ssh_config /etc/ssh

# SSH client setup
mkdir /root/.ssh
cp /share/id_rsa /root/.ssh
cp /share/id_rsa.pub /root/.ssh
cp /share/id_rsa.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/id_rsa

# Start SSH daemon
/usr/sbin/sshd
