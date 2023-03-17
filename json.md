# JSON

The enclaves make use of JSON to communicate with the client. Here, we define what parameters we expect and what they do.

## Client input

The client sends one JSON object as input. This JSON contains the encrypted input as a nested string in Base64 format.

```json
{
    "encrypted-input": (type: String; Encoded as Base64),
    "gb": {
        "gx" : (type: String; Encoded as Base64),
        "gy" : (type: String; Encoded as Base64)
    }
}
```

The encrypted-input should look like this once decrypted. The "input" field will be directly handed over to the script for processing.

```json
{
    "input": (type: JSON),
    "nonce": (type: String),
    "sign-output" : (type: Boolean)
}
```

## Server output

The server will output an encrypted JSON object (As Base64 string):

```json
{
    "nonce": (type: String),
    "script-hash": (type: String; Encoded as Base64),
    "signature": (type: String; Encoded as Base64),
    "output": (type:JSON)
}
```

## Server key announcement

The server announces its public key triple together with a quote and the MRENCLAVE value that the keys are generated for.

```json
{
    "keys":{
        "session_dh": (type: String; Encoded as Base64),
        "signing_pk": (type: String; Encoded as Base64),
        "measurements_pk": (type: String; Encoded as Base64)
    },
    "quote": (type: String; Encoded as Base64),
    "target": (type: String; Encoded as Base64)
}
```