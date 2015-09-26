Keyrings
====================

* RSA encryption/RSA signing, 2048 bits
* two keyrings: senders_keyring.gpg and recipients_keyring.gpg
* passwords: "sender" and "recipient"
* use `gpg_sender`/`gpg_sender` as commands that operate on the correct keyrings



Generate new keyrings
------------------------

```
rm -rf {sender,recipient}.gpg.d
mkdir  {sender,recipient}.gpg.d
chmod 700  {sender,recipient}.gpg.d

cat sender.tpl |./gpg_sender --yes --batch --gen-key
cat recipient.tpl |./gpg_recipient --yes --batch --gen-key

./gpg_sender -a --export sender@example.com | ./gpg_recipient --import
./gpg_recipient --yes --edit-key sender@example.com
# then trust the key ultimately (enter "trust" then answer 5. enter "q")

./gpg_recipient -a --export recipient@example.com | ./gpg_sender --import
./gpg_sender --yes --edit-key recipient@example.com
# then trust the key ultimately (enter "trust" then answer 5. enter "q")
```
