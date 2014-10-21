#!/bin/bash

if [ $# -ne 2 ]; then
  echo "./rot-gen.sh [ISD ID] [AD ID]"
  exit 1;
fi

isd=$1
ad=$2

country=CH
state=Zurich
locality=Zurich
organization=ETHZ
organizationalunit=NetSec

version=0
issueDate="Jul 01 21:15:39 2013 GMT"
expDate="Jun 29 21:14:51 2023 GMT"
policyThreshold=1
certificateThreshold=1

xmlHdrText1='<?xml version="1.0" standalone="no" ?>'
xmlHdrText2='<!DOCTYPE document SYSTEM "rot.dtd">'
hdrText='<header>\n\t<version>version_field</version>\n\t<issueDate>issue_field</issueDate>\n\t<expireDate>expire_field</expireDate>\n\t<ISDID>isdid_field</ISDID>\n\t<policyThreshold>policy_threshold_field</policyThreshold>\n\t<certificateThreshold>cert_threshold_field</certificateThreshold>\n</header>\n\n'
coreAdText='<coreADs>\n\t<coreAD>\n\t\t<ADID>adid_field</ADID>\n\t\t<len>cert_len_field</len>\n\t\t<cert>cert_field</cert>\n\t</coreAD>\n\n</coreADs>\n'
sigText='\n<signatures>\n\t<coreAD>\n\t\t<ADID>adid_field</ADID>\n\t\t<len>sig_len_field</len>\n\t\t<sign>sig_field</sign>\n\t</coreAD>\n\n</signatures>\n\n</ROT>\n'

filename=ISD$isd/rot-isd$isd-0.xml
privkey=ISD$isd/rot-isd$isd.key
certFile=ISD$isd/rot-isd$isd.crt

commonname=isd$isd.com
email=isd$isd@domain.com

{
  openssl genrsa -out $privkey 2048
  openssl req -new -x509 -days 3650 -extensions v3_ca -key $privkey -out $certFile \
          -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email/"
} &> /dev/null

printf %s "${xmlHdrText1}" > $filename
printf "\n" >> $filename
printf %s "${xmlHdrText2}" >> $filename
printf "\n<ROT>\n\n" >> $filename
printf $hdrText >> $filename
printf $coreAdText  >> $filename

sed -i -e "s/version_field/$version/g" $filename
sed -i -e "s/issue_field/$issueDate/g" $filename
sed -i -e "s/expire_field/$expDate/g" $filename
sed -i -e "s/policy_threshold_field/$policyThreshold/g" $filename
sed -i -e "s/cert_threshold_field/$certificateThreshold/g" $filename
sed -i -e "s/isdid_field/$isd/g" $filename
sed -i -e "s/adid_field/$ad/g" $filename

IFS=$'\n' certString=$(cat $certFile)
unset IFS
certLen=${#certString}
certString=$(echo $certString | sed 's| |\\n|g')
certString=$(echo $certString | sed 's|BEGIN\\nCERTIFICATE|BEGIN CERTIFICATE|g')
certString=$(echo $certString | sed 's|END\\nCERTIFICATE|END CERTIFICATE|g')
sed -i -e "s|cert_field|$certString|g" $filename
sed -i -e "s/cert_len_field/$certLen/g" $filename

sigString=$(openssl dgst -sha1 -sign $privkey $filename |base64)
sigLen=${#sigString}
sigString=$(echo $sigString | sed 's| |\\n|g')

printf $sigText >> $filename

sed -i -e "s/adid_field/$ad/g" $filename
sed -i -e "s|sig_field|$sigString|g" $filename
sed -i -e "s/sig_len_field/$sigLen/g" $filename
