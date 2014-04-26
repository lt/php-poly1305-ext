Curve25519 PHP extension
========================

This extension is a thin wrapper around [Andrew Moon's poly1305-donna](https://github.com/floodyberry/poly1305-donna) implementation

### Usage:

TODO

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
