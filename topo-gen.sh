#!/bin/bash

if [ ! -f 'ADToISD' ]; then
  echo "ADToISD missing...aborting"
  exit 1
fi

if [ ! -f 'ADRelationships' ]; then
  echo "ADRelationships missing...aborting"
  exit 1
fi

if [ ! -f 'rot-gen.sh' ]; then
  echo "rot-gen.sh missing...aborting"
  exit 1
fi

echo "Deleting all previously created ISD folders"
rm -rf ISD*

#Generate ADs' keys and certificates
country=CH
state=Zurich
locality=Zurich
organization=ETHZ
organizationalunit=NetSec

while read ad isd r || [[ -n "$line" ]]; do
	echo $ad $isd
	if [ $r -eq 0 ]; then
		isds[$isd]=$ad
	fi

	mkdir -p ISD$isd/certificates
    	mkdir -p ISD$isd/configurations
    	mkdir -p ISD$isd/private_keys
    	mkdir -p ISD$isd/topologies

	privkey=ISD$isd/private_keys/isd$isd-ad$ad-0.key
	certFile=ISD$isd/certificates/isd$isd-ad$ad-0.crt
	commonname=isd$isd-ad$ad.com
	email=isd$isd-ad$ad@domain.com
	{
	openssl genrsa -out $privkey 2048
	openssl req -new -x509 -days 3650 -extensions v3_ca -key $privkey -out $certFile \
	        -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email/"
	} &> /dev/null
done < ADToISD

#Generate root of trust files
echo "Generate Root of Trust Files"
for isd in "${!isds[@]}"; do
	./rot-gen.sh $isd ${isds[$isd]}
done

#Execute Topology Generator
make

echo "Executing SCION Configuration Builder"
./conf-gen
