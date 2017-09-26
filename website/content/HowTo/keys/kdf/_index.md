{
"title" : "Derive more keys from a key",
"description": "For many use cases it is desirable to derive multiple keys from one master key. This not only increases security, it also greatly simplifies key management.",
"tags" : [
    "howto",
    "key derivation", "TODO"
],
"categories" : [
    "keys"
]
}

For many use cases it is desirable to derive multiple keys from one master key. This not only increases security, it also greatly simplifies key management.

{{<mermaid align="left">}}
graph LR;
    MK(fa:fa-key  Masterkey) --> KDF[fa:fa-cog Key Derivation Function]
    S(Salt) --> KDF
    ID(Context + SubKey ID) --> KDF
    KDF --> SK(fa:fa-key Subkey)
    SK -.-> AES[fa:fa-cog AES]
{{< /mermaid >}}

TODO

## Examples
{{% children description="true" depth="1"  %}}

