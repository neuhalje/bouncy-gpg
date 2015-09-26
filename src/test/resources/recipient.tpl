%echo Generating recipient key
          Key-Type: RSA
          Key-Length: 2048
          Subkey-Type: RSA
          Subkey-Length: 2048
          Name-Real: Rezi Recipient
          Name-Comment: Pasword: recipient
          Name-Email: recipient@example.com
          Expire-Date: 0
          Passphrase: recipient
          %commit
          %echo done
