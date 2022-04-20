from jwcrypto import jwk, jwt
from argparse import ArgumentParser
from time import time
import json

parser = ArgumentParser("Issue a JWT")
parser.add_argument('issuer',  help='KID of Issuer')
parser.add_argument('claims', help='JSON file with claims')
parser.add_argument('--valid-seconds', default=None, help='Set expiry to number of seconds in future')
args = parser.parse_args()


try: 
    key = jwk.JWK.from_json(open(f"{args.issuer}.private").read())
except FileNotFoundError: 
    print('Issuer key file not found')
    exit(0)
except json.JSONDecodeError: 
    print('Cannot read issuer key file')
    exit(0)


try: 
    claims =json.load(open(args.claims))
except FileNotFoundError: 
    print('Claims file not found')
    exit(0)
except json.JSONDecodeError: 
    print('Cannot read claims file')
    exit(0)


claims['iat'] = int(time())
if args.valid_seconds is not None: 
    claims['exp'] = int(time()) + int(args.valid_seconds)

jwt_obj = jwt.JWT(header={'alg':'ES256', 'typ':'JWT', 'kid':key['kid']}, claims=claims)
jwt_obj.make_signed_token(key=key)

print(jwt_obj.serialize())
