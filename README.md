# netsecps2
This repository uses the primitives layer of the cryptography python library in order to create a PGP like system.

## Encrypting   
- Create a AESGCM key and nonce and use them to encrypt a given file
- Use a given RSA private key to digitally sign the encrypted message
- Encrypt the key and nonce using a given RSA public key (the receivers RSA public key)
- Concatenate the encrypted versions of the message, nonce, and key 
- Concatenate that string with the signature (not encrypted) and write it to a targeted file

## Decrypting  
- Pull in the encrypted file
- Seperate out the message, key, nonce, and signature components.
- Check the signature with the senders public key and see if it validates against the encrypted message
- If not quit out as the message has been altered in some way, further action could at best be inefficient and at worst dangerous
- If it does validate then use your (the receivers RSA private key) to decrypt the key and nonce for AESGCM
- Use those two pieces of information to initialize the AESGCM module and use it to decrypt the message to plain text
- Write out the plain text to a targeted file.  

## Included Script  
There is an included script that will allow a user to check if the program is working correctly by doing the encryption and decryption steps followed by a diff command on the output file vs the original.  The file passes if the diff returns True
