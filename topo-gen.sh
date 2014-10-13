#!/bin/bash

if [ ! -f 'AsToTD' ]; then
  echo "AsToTD missing...aborting"
  exit 1
fi

if [ ! -f 'AsRelationship' ]; then
  echo "AsRelationship missing...aborting"
  exit 1
fi

if [ ! -f 'rot-gen.sh' ]; then
  echo "rot-gen.sh missing...aborting"
  exit 1
fi

echo "Deleting all previously created TD folders"
rm -rf TD*

#Generate ADs' keys and certificates
country=CH
state=Zurich
locality=Zurich
organization=ETHZ
organizationalunit=NetSec

while read ad td r || [[ -n "$line" ]]; do

	if [ $r -eq 0 ]; then
		tds[$td]=$ad
	fi

	mkdir -p TD$td/certificates
    mkdir -p TD$td/configurations
    mkdir -p TD$td/private_keys
    mkdir -p TD$td/topologies

	privkey=TD$td/private_keys/td$td-ad$ad-0.key
	certFile=TD$td/certificates/td$td-ad$ad-0.crt
	commonname=td$td-ad$ad.com
	email=td$td-ad$ad@domain.com
	{
	openssl genrsa -out $privkey 2048
	openssl req -new -x509 -days 3650 -extensions v3_ca -key $privkey -out $certFile \
	        -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email/"
	} &> /dev/null
done < AsToTD

#Generate root of trust files
echo "Generate Root of Trust Files"
for td in "${!tds[@]}"; do
	./rot-gen.sh $td ${tds[$td]}
done

#Execute Topology Generator
make

echo "Executing SCION Configuration Builder"
./conf-gen
