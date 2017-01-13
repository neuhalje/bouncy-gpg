#!/usr/bin/env bash

[ -f zip_encrypted_armored_unsigned.zip.gpg ] && rm zip_encrypted_armored_unsigned.zip.gpg
zip - -r ../../../main |  gpg --batch --yes --no-default-keyring --homedir ../sender.gpg.d -e -a -r recipient@example.com -o zip_encrypted_armored_unsigned.zip.gpg

##

[ -f zip_encrypted_binary_unsigned.zip.gpg ] && rm zip_encrypted_binary_unsigned.zip.gpg
zip - -r ../../../main |  gpg --batch --yes --no-default-keyring --homedir ../sender.gpg.d -e -r recipient@example.com -o zip_encrypted_binary_unsigned.zip.gpg

[ -f zip_encrypted_binary_signed.zip.gpg ] && rm zip_encrypted_binary_signed.zip.gpg
zip -  -r ../../../main |   gpg  --passphrase sender --yes --batch --yes --no-default-keyring --homedir ../sender.gpg.d -e -s -r recipient@example.com -o zip_encrypted_binary_signed.zip.gpg

[ -f zip_encrypted_armor_signed.zip.gpg ] && rm zip_encrypted_armor_signed.zip.gpg
zip -  -r ../../../main |   gpg  --passphrase sender --yes --batch --yes --no-default-keyring --homedir ../sender.gpg.d -e -a -s -r recipient@example.com -o zip_encrypted_armor_signed.zip.gpg
