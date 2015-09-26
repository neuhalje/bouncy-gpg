%echo Generating sender key
          Key-Type: RSA
          Key-Length: 2048
          Subkey-Type: RSA
          Subkey-Length: 2048
          Name-Real: Sven Sender
          Name-Comment: Pasword: sender
          Name-Email: sender@example.com
          Expire-Date: 0
          Passphrase: sender
          %commit
          %echo done
