full-stack messaging application


RSA for symmetric key exchange
AES for fast encryption of message content
HMAC for integrity validation
Use Base64 for message transmission
Client App (select one Java / Python / Node / RUST ): GUI or CLI

Serialize the Student object from memory into a payload document JSON string
Uses the RSA public key to encrypt the symmetric key
Encrypts outgoing messages using the AES session symmetric key
Sign the message with HMAC for tamper protection using the symmetric key
Server API (Web Services (SOAP or REST): Java / Python / Node / RUST select one) GUI or CLI

Starts a Web Service listening REST or SOAP
Generates the RSA public and private keys
Shares the public key
Receives the message and HMAC payload from the client
Checks the HMAC for message tampering
Decrypts the incoming message using the AES session key
