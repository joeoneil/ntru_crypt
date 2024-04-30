# NTRU Crypt

This is a minimal pure Rust implementation of the NTRU Public key cryptosystem,
done as part of a project for a cryptography class. It implements the NTRU 
system to the specification of the original (1998) paper, including the levels
of security recommended by that paper. Several enhancements to the algorithm
have been made since, as well as hightened levels of security to combat the
increase in computational power available to attackers. Do not trust this
software to securely encrypt your data to a modern, reasonable standard. Do
trust this software to encrypt your data such that an attacker in 1998 could
not feasably retrieve it. 

This implementation is not published on crates.io as it is strictly inferior to
other pure rust implementations in terms of scope and speed, as it is only a
proof of concept demonstration. To install it to your system globally, you will
need rust to be installed (see https://https://www.rust-lang.org/tools/install).
This can then be installed by

```
git clone https://github.com/joeoneil/ntru_crypt
cd ntru_crypt
cargo install --path .
```

# Usage

`ntru_crypt` provides 3 subcommands, `keygen`, `encrypt`, and `decrypt`, which
do exactly what they say. That is, generate keys, encrypt files, and decrypt
files. 

## Key generation

keygen takes two arguments `-s n` where n is the desired security level
(between 0 and 3), as well as the name `-f [name]` which defaults to 'id\_ntru'.
Note that while this has a similarity in name to ssh-keygen, these keys cannot
be used as ssh keys, and the similarity ends at the name.

```
ntru_crypt -s 2 --filename l2_key
```

Will make a key pair `l2_key` containing the private key and `l2_key.pub`
contianing the public key.

## Encryption / Decryption

encrypt and decrypt take similar arguments which are as follows:

`-if, --input-file` the input file (plaintext or ciphertext)

`-kf, --key-file` the key (public or private) to use

`-ifmt, --input-format` the format of the input data (decryption only)

`-of, --output-format` the format of the output data

Encryption and decryption support ciphertexts in base64, base64 web, and binary
formats. Decryption can also decode to base64 data, although I'm not sure why
you would want that (but it is an option). Setting the output format to 'Text'
for decryption will validate that the output data is valid UTF-8, but will not
modify the resultant data. Decrypting a binary file with output format 'Text'
will (likely) fail if the binary is not valid UTF-8.

More information about subcommands and their usage can also be found by 
`ntru_crypt --help` or `ntru_crypt [subcommand] --help`.
