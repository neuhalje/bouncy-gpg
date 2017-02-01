%echo Generating sender key
          Key-Type: RSA
          Key-Length: 2048
          Subkey-Type: RSA
          Subkey-Length: 2048
          Name-Real: Sonja Sender
          Name-Comment: Pasword: another_sender
          Name-Email: another_sender@example.com
          Expire-Date: 0
          Passphrase: another_sender
          %commit
          %echo done
