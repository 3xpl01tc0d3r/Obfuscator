# Obfuscator
----

The program is designed to obfuscate the shellcode.
Currently the tool supports 2 encryption.

```
1) XOR
2) AES
```

The tool accepts shellcode in 4 formats.

```
1) base64
2) hex
3) c
4) raw
```

### Command Line Usage

```
Usage           Description
-----           -----------
/f              Specify the format of the shellcode
                base64
                hex
                c
                raw
/enc            Specify the encryption type (aes or xor) in which the shellcode will be encrypted
/key            Specify the key that will be used to encrypt the shellcode (default = SuperStrongKey)
/path           Specify the path of the file that contains the shellcode
/url            Specify the url where the shellcode is hosted
/o              Specify the file path to save the encrypted shellcode (default = output.bin)
/help           Show help
```

### Blog Post

[https://3xpl01tc0d3r.blogspot.com/2020/08/obfuscator.html](https://3xpl01tc0d3r.blogspot.com/2020/08/obfuscator.html)