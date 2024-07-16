#!/bin/bash

FNAME="test.p12"
echo "Creating p12 keystore"
if [[ "$1" == "" ]]; then
	echo ""
	echo " *** Missing store password, enter on command line *** "
	echo " *** Should consist of storepass  i.e. vaultKey    *** "
	echo ""
	exit 1
fi

if [[ -f "$FNAME" ]]; then
  rm "$FNAME"
fi
keytoolVer22=$(command -v keytool | grep jdk-22 | wc -l | xargs)
if [[ "$keytoolVer22" -gt 0 ]]; then
  echo "version 22 found, keytool from jdk 18 and below required"
fi

if [[ -f /Library/Java/JavaVirtualMachines/jdk-18.0.1.jdk/Contents/Home/bin/keytool ]]; then
  # use client_id as alias value, use client_secret as password
  # select name, auth_flow, response_type, client_id, client_secret from user_ords_clients
  echo "mytestsecret" | /Library/Java/JavaVirtualMachines/jdk-18.0.1.jdk/Contents/Home/bin/keytool -importpass -storetype pkcs12 -alias "mytestalias" -keystore "$FNAME" -storepass $1
else
  echo "no keytool application found"
fi