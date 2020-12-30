  Before running server.py and client.py, it is necessary to extract the certificate from a known citizen card as cert.der and put it in client/ and to encrypt it for the server by running server/file_encrypt.py. It is also necessary to move client/root_ca.crt to /etc/ssl/certs/.

  client/cipher_suites.py and server/cipher_suites.py contain support for both the client and the server regarding cipher suites.
  client/root_ca.crt is the root CA that issued the server's certificate.
  server/client_certificates/ is used to store the encrypted client's certificate.
  server/file_encrypt.py encrypts both the media files and the client's certificate for use in the server and returns the key used for it, it also contains ways to decrypt them used for testing.
  server/server_cert.crt is the server's certificate.
  server/server_cert_priv_key.pem is the server's certificate's private key.
  server/server_rest_key is the key used for encryption and decryption of the media files and the client certificates.
