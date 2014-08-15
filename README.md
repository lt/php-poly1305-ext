Poly1305 PHP extension
========================

This extension is a thin wrapper around [Andrew Moon's poly1305-donna](https://github.com/floodyberry/poly1305-donna) implementation

### Usage:

Generate an authenticator using a 32 byte unique key

```
$authenticator = poly1305_authenticate($key, $message);
```

Verify the authenticity using the authenticator for that key

```
$valid = poly1305_verify($authenticator, $key, $message);
```

Remember that *a key must not be used more than once*

### How to install:

```
git clone git://github.com/lt/php-poly1305.git
cd php-poly1305
phpize
./configure
make
sudo make install
```
Finally add `extension=poly1305.so` to your /etc/php.ini


# Poly1305-AES

This extension can be used to compute Poly1305-AES MACs. You will need a way of performing AES encryption to do this. Most people have the OpenSSL or MCrypt extensions that can do this.

### OpenSSL

`$k$r` is 32 byte random key, and `$n` is unique nonce for each message. By changing the nonce each time, the key is able to be re-used between messages.

```
$k = '0123456789012345';
$r = '0123456789012345';
$n = '0123456789012345';

$aeskn = openssl_encrypt($n, 'aes-128-ecb', $k,
    OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

$authenticator = poly1305_authenticate($r . $aeskn, $message);
```

### MCrypt

`$k$r` is 32 byte random key, and `$n` is unique nonce for each message. By changing the nonce each time, the key is able to be re-used between messages.

```
$k = '0123456789012345';
$r = '0123456789012345';
$n = '0123456789012345';

$aeskn = mcrypt_encrypt('rijndael-128', $k, $n, 'ecb');

$authenticator = poly1305_authenticate($r . $aeskn, $message);
```
