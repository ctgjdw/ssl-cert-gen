#!/bin/bash

rm -f -r /certs/ca
rm -f -r /certs/keycloak
rm -f -r /certs/nginx

mkdir -p /certs/{ca,keycloak,nginx}

# Generate root CA (ignore if you already have one)
openssl genrsa -out /certs/ca/ca.key 4096
openssl req -new -x509 -sha256 -days 36500 -subj "/CN=ca" -key /certs/ca/ca.key -out /certs/ca/ca.pem

# Generate Keycloak certificate, signed by your CA
openssl genrsa -out /certs/keycloak/keycloak-temp.key 4096
openssl pkcs8 -inform PEM -outform PEM -in /certs/keycloak/keycloak-temp.key -topk8 -nocrypt -v1 PBE-SHA1-3DES -out /certs/keycloak/keycloak.key
openssl req -new -subj "/CN=keycloak" -key /certs/keycloak/keycloak.key -out /certs/keycloak/keycloak.csr
openssl x509 -days 36500 -req -extfile <(printf "subjectAltName=DNS:keycloak,DNS:<ALT_DNS>,IP:<IP_ADDR>") -in /certs/keycloak/keycloak.csr -CA /certs/ca/ca.pem -CAkey /certs/ca/ca.key -CAcreateserial -sha256 -out /certs/keycloak/keycloak.pem
rm /certs/keycloak/keycloak-temp.key /certs/keycloak/keycloak.csr

# Generate nginx certificate, signed by your CA
openssl genrsa -out /certs/nginx/nginx-temp.key 4096
openssl pkcs8 -inform PEM -outform PEM -in /certs/nginx/nginx-temp.key -topk8 -nocrypt -v1 PBE-SHA1-3DES -out /certs/nginx/nginx.key
openssl req -new -subj "/CN=nginx" -key /certs/nginx/nginx.key -out /certs/nginx/nginx.csr
openssl x509 -days 36500 -req -extfile <(printf "subjectAltName=DNS:nginx,DNS:<ALT_DNS>,IP:<IP_ADDR>") -in /certs/nginx/nginx.csr -CA /certs/ca/ca.pem -CAkey /certs/ca/ca.key -CAcreateserial -sha256 -out /certs/nginx/nginx.pem
rm /certs/nginx/nginx-temp.key /certs/nginx/nginx.csr

# Generate keystore
openssl pkcs12 -export -name server-cert -in /certs/ca/ca.pem -inkey /certs/ca/ca.key -out /certs/keycloak/keystore.p12 -password "pass:$KEYSTORE_PWD"
keytool -importkeystore -destkeystore /certs/keycloak/truststore.jks -srckeystore /certs/keycloak/keystore.p12 -srcstoretype pkcs12 -alias server-cert -srcstorepass "$KEYSTORE_PWD" -deststorepass "$KEYSTORE_PWD"
keytool -import -alias adlds-root-cert -file /certs/adlds/ca.cer -keystore /certs/keycloak/truststore.jks -storepass "$KEYSTORE_PWD" -noprompt
