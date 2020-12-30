  Before running <b>server.py</b> and <b>client.py</b>, it is necessary to extract the certificate from a known citizen card into a file named <b>cert.der</b> and put it in <b>client/</b> and to encrypt it for the server by running <b>server/file_encrypt.py</b>. It is also necessary to move <b>client/root_ca.crt</b> to <b>/etc/ssl/certs/</b>.

<b>client/cipher_suites.py</b> and server/cipher_suites.py contain support for both the client and the server regarding cipher suites.

<b>client/root_ca.crt</b> is the root CA that issued the server's certificate.

<b>server/client_certificates/</b> is used to store the encrypted client's certificate.

<b>server/file_encrypt.py</b> encrypts both the media files and the client's certificate for use in the server and returns the key used for it, it also contains ways to decrypt them used for testing.

<b>server/server_cert.crt</b> is the server's certificate.

<b>server/server_cert_priv_key.pem</b> is the server's certificate's private key.

<b>server/server_rest_key</b> is the key used for encryption and decryption of the media files and the client certificates.
