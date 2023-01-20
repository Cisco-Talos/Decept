#!/bin/bash

check_return() {
    if [ $? -ne 0 ]; then
        echo "[x.x] Failed this step, exiting!"
        exit
    fi 
}

#echo "[1.1] Generating ECDSA client key"
#openssl ecparam -genkey -out mitm_ecdh.key -name secp256k1
#check_return

#echo "[2.2] Generating ECDSA public key"
#openssl pkey -in mitm_ecdh.key -pubout -out mitm_ecdh.pem
#check_return

echo -e "\e[30;48;5;82m[1.1] Generating RootCA key and cert\e[0m"
openssl genrsa -out mitmRoot.key 4096 
check_return 

openssl req -x509 -new -nodes -key mitmRoot.key -sha256 -days 3650 -out mitmRoot.crt
check_return 

echo -e "\e[30;48;5;82m[2.2] Generating intermediate RSA aes256 client key\e[0m"
openssl genrsa -out mitm_inter.key 4096
check_return

echo -e "\e[30;48;5;82m[3.3] Generating intermediate client CSR\e[0m" 
echo -e "\e[30;48;5;79m[4.4] Note: you must create with different attributes than root, or else verification will fail.\e[0m"
openssl req -new -key mitm_inter.key -out mitm_inter.csr
check_return

echo -e "\e[30;48;5;82m[5.5] Signing Intermediate CSR with RootCA\e[0m"
openssl x509 -req -days 3650 -in mitm_inter.csr -CA mitmRoot.crt -CAkey mitmRoot.key\
                             -CAcreateserial -out mitm_inter.crt -sha256 
check_return

echo -e "\e[30;48;5;82m[6.6] Verifying Intermediate with RootCA\e[0m"
openssl verify -verbose -x509_strict -CAfile mitmRoot.crt mitm_inter.crt
check_return

dst=certchain-`date | tr " " "-"`
mkdir $dst
mv mitm* $dst 
echo "[^_^] All done!"
