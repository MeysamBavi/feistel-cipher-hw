# FCH
A simple encryption algorithm based on Feistel system in Go

## Run
### Compile
```bash
go build -o fch main.go
```
### Encrypt and Decrypt
```bash
cat LICENSE | ./fch -k 1122334455667788 enc | ./fch -k 1122334455667788 dec
```
