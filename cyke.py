import base64

# Provided string
encoded_str = "CIUKSFEBGZJL2OVMDDTAR=Q4N5WXHP3"

# Base32 and Base64 decoding attempts
try:
    # Trying to decode assuming it's Base32 first
    base32_decoded = base64.b32decode(encoded_str + "=" * ((8 - len(encoded_str) % 8) % 8)).decode('utf-8', 'ignore')
except Exception as e:
    base32_decoded = str(e)

try:
    # Trying to decode assuming it's Base64
    base64_decoded = base64.b64decode(encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)).decode('utf-8', 'ignore')
except Exception as e:
    base64_decoded = str(e)

base32_decoded, base64_decoded
