# Identity-based Encryption

Prototype of identity-based encryption based on [Boneh-Franklin scheme](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf), leveraging [gnark-crypto library](https://github.com/Consensys/gnark-crypto).


````
go build
./id-based-encryption
./id-based-encryption -mode tpgk
````

## Client APIs

GET **/master-public-key**

POST **/encrypt**

````
{
    "Id": "me@gmail.com",
    "Plaintext": "test"
}
````

POST **/decrypt**

````
{
    "UserPrivKey": "04d1...",
    "Ciphertext": "7b22..."
}
````

***

## TPKG APIs

GET **/master-public-key**

POST **/extract**
````
{
    "Id": "me@gmail.com"
}
```