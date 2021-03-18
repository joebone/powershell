#!/bin/sh

# Receives your Windows username as only parameter.


USERNAME=$(powershell.exe '$env:UserName')

apk add curl git 


curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.16.0/bin/linux/amd64/kubectl
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

windowsUser=$USERNAME # $1

mkdir -p ~/.kube
ln -sf "/mnt/c/users/$windowsUser/.kube/config" ~/.kube/config

kubectl version