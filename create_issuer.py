from jwcrypto import jwk
from base64 import b64decode
import json

key = jwk.JWK.generate(kty='EC')

def pad64(s):
    return s+{0:"",1:"==",2:"="}.get(len(s)%3)

# Make Key ID == first 8 bytes of thumbprint in HEX representation
key['kid'] = b64decode(pad64(key.thumbprint()))[:8].hex()

with open(f"{key['kid']}.private", "w") as keyfile: 
    json.dump(key.export(private_key=True, as_dict=True), keyfile, indent=4)

with open(f"{key['kid']}.public", "w") as keyfile: 
    json.dump(key.export(private_key=False, as_dict=True), keyfile, indent=4)