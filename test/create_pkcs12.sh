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
javaVer=$(java -version 2>&1 | grep version | awk '{ print $3 }' | xargs | sed -e 's/\./ /g' | awk '{print $1}')
if [[ "$javaVer" -gt 17 ]]; then
  echo "keytool version above 17.x will cause issues"
fi

if [[ $(command -v keytool) ]]; then
  # use client_id as alias value, use client_secret as password
  # select name, auth_flow, response_type, client_id, client_secret from user_ords_clients
  echo "mytestsecret" | keytool -importpass -storetype pkcs12 -alias "mytestalias" -keystore "$FNAME" -storepass $1
  echo "mytestsecret2" | keytool -importpass -storetype pkcs12 -alias "mytestalias2" -keystore "$FNAME" -storepass $1
else
  echo "no keytool application found"
fi