{
"title" : "Derive more keys from a key",
"tags" : [
    "howto",
    "key derivation", "TODO"
],
"categories" : [
    "keys"
]
}


{{<mermaid align="left">}}
graph LR;
    MK(fa:fa-key  Masterkey) --> KDF[fa:fa-cog Key Derivation Function]
    S(Salt) --> KDF
    ID(Context + SubKey ID) --> KDF
    KDF --> SK(fa:fa-key Subkey)
    SK -.-> AES[fa:fa-cog AES]
{{< /mermaid >}}

TODO
