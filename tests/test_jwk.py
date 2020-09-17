from jose import jwk
from jose.exceptions import JWKError
from jose.backends.base import Key
from jose.backends import ECKey, RSAKey, HMACKey, AESKey
from jose.utils import base64url_decode

import pytest

hmac_key = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
}

rsa_key = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}

ec_key = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
}


class TestJWK:

    def test_interface(self):

        key = jwk.Key("key", "ALG")

        with pytest.raises(NotImplementedError):
            key.sign('')

        with pytest.raises(NotImplementedError):
            key.verify('', '')

    def test_invalid_hash_alg(self):
        with pytest.raises(JWKError):
            key = HMACKey(hmac_key, 'RS512')

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, 'HS512')

        with pytest.raises(JWKError):
            key = ECKey(ec_key, 'RS512')  # noqa: F841

    def test_invalid_jwk(self):

        with pytest.raises(JWKError):
            key = HMACKey(rsa_key, 'HS256')

        with pytest.raises(JWKError):
            key = RSAKey(hmac_key, 'RS256')

        with pytest.raises(JWKError):
            key = ECKey(rsa_key, 'ES256')  # noqa: F841

    def test_RSAKey_errors(self):

        rsa_key = {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB"
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, 'HS256')

        rsa_key = {
            "kty": "oct",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB"
        }

        with pytest.raises(JWKError):
            key = RSAKey(rsa_key, 'RS256')  # noqa: F841

    def test_construct_from_jwk(self):

        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        }

        key = jwk.construct(hmac_key)
        assert isinstance(key, jwk.Key)

    def test_construct_EC_from_jwk(self):
        key = ECKey(ec_key, algorithm='ES512')
        assert isinstance(key, jwk.Key)

    def test_construct_from_jwk_missing_alg(self):

        hmac_key = {
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        }

        with pytest.raises(JWKError):
            key = jwk.construct(hmac_key)

        with pytest.raises(JWKError):
            key = jwk.construct("key", algorithm="NONEXISTENT")  # noqa: F841

    def test_get_key(self):
        hs_key = jwk.get_key("HS256")
        assert hs_key == HMACKey
        assert issubclass(hs_key, Key)
        assert issubclass(jwk.get_key("RS256"), Key)
        assert issubclass(jwk.get_key("ES256"), Key)

        assert jwk.get_key("NONEXISTENT") is None

    @pytest.mark.skipif(AESKey is None, reason="No AES provider")
    def test_get_aes_key(self):
        assert issubclass(jwk.get_key("A256CBC-HS512"), Key)

    def test_register_key(self):
        assert jwk.register_key("ALG", jwk.Key)
        assert jwk.get_key("ALG") == jwk.Key

        with pytest.raises(TypeError):
            assert jwk.register_key("ALG", object)

    def test_verify_message_str(self):
        token = \
            "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWV" \
            "lZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kb" \
            "ywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwg" \
            "YW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGt" \
            "ub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkf" \
            "BBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
        key = jwk.construct(hmac_key)
        message, encoded_sig = token.rsplit('.', 1)
        decoded_sig = base64url_decode(encoded_sig)
        assert key.verify(message, decoded_sig)
