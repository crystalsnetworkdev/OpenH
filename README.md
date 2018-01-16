
# OpenHL (Open Hash Library)

**OpenHL** is a library of hash functions written in C:
- SHA-1
- SHA-2
	- SHA-256
	- SHA-224
	- SHA-512
	- SHA-384
	- SHA-512/256
	- SHA-512/224
- MD4
- MD5

## Installing

### Windows (MSYS)

```
git clone https://github.com/loreloc/OpenHL.git
cd OpenHL
cmake . -DCMAKE_INSTALL_PREFIX=/mingw64
make
make install
```

### Linux

```
git clone https://github.com/loreloc/OpenHL.git
cd OpenHL
cmake .
make
make install
```

## License
**OpenHL** is under zlib license.


