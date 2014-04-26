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
