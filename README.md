## Introduction
This script is designed to obtain a key PBKDF2-HMAC-SHA256 and then decrypt the hash from the website 
<a style="text-decoration: none;" href="https://absolutesolver.com/a9f3b7c2d1e4/" target="_blank">
AbsoluteSolver.com </a>

## Install

- **You must have python 3.14 or higher installed**
- Download the repository data to your disk.
- Set the dependencies.
```bash
py -m pip download -r requirements.txt
```
- In the main.py code, you will need to change the variables to the ones you need.
  - SALT_B64 - Your salt (base64)
  - NONCE_B64 - Nonce/IV (12 bytes)
  - CIPHERTEXT_B64 - Encrypted data (base64)
  - AUTH_TAG_B64 - Authentication tag (base64)
- Add words to arrays from the riddle.
  - They are all called arr1 - arr6
  - Try not to add too many words!
- Launch main.py
```bash
py main.py
```

## Afterword
Then you just have to wait for the code to do its job and give us a decryption or error. All incorrect passwords will be saved in fail_pass.log and all these incorrect passwords will not be verified in the future. At the moment, I have checked 6242 passwords for 1 problem. (I didn't check the other issues)

