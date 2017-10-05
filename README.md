# netsecps2
This repository uses the primitives layer of the cryptography python library in order to create a PGP like system.

## Encrypting   
- Use a given RSA private key to digitally sign the plain text message
- Create a AESGCM key and nonce and use them to encrypt the message and signature
- Encrypt the key and nonce using a given RSA public key (the receivers RSA public key)
- Concatenate the encrypted versions of the message, nonce, key and write it to a targeted file

## Decrypting  
- Pull in the encrypted file
- Seperate out the message, key, and nonce components.
- Decrypt the key and nonce using the receivers private key
- Use them to decrypt the message and seperate out the signature
- Check if the signature is valid if so continue, if not raise error and inform the user of the invalid signature.
- Write out the plain text to the targeted file.  

## Included Script  
There is an included script that will allow a user to check if the program is working correctly by doing the encryption and decryption steps followed by a diff command on the output file vs the original.  The file passes if the diff returns True
