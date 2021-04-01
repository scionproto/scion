#!/bin/bash
set -ex

# SSH daemon setup
mkdir /run/sshd
cp /share/ssh_config /etc/ssh

# SSH client setup
mkdir /root/.ssh
cp /share/id_rsa /root/.ssh
cp /share/id_rsa.pub /root/.ssh
cp /share/id_rsa.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/id_rsa

# Start SSH daemon
/usr/sbin/sshd
