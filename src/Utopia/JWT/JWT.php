<?php

namespace Utopia\JWT;

use Exception;

class JWT
{
    private const ALGORITHMS = [
        'ES384' => ['openssl', OPENSSL_ALGO_SHA384],
        'ES256' => ['openssl', OPENSSL_ALGO_SHA256],
        'ES256K' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS256' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384' => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512' => ['openssl', OPENSSL_ALGO_SHA512],
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
    ];

    /**
     * @throws Exception
     */
    public static function decode(
        string $jwt,
        string $key,
        string $algorithm,
        array &$headers = null
    ): array {
        $timestamp = \time();

        if (empty($key)) {
            throw new Exception('Missing key');
        }

        $segments = \explode('.', $jwt);

        if (\count($segments) !== 3) {
            throw new Exception('Wrong number of segments');
        }

        [$headers64, $payload64, $signature64] = $segments;

        $headers = \json_decode(static::safeBase64Decode($headers64), true);
        $payload = \json_decode(static::safeBase64Decode($payload64), true);
        $signature = static::safeBase64Decode($signature64);

        if (\is_null($headers)) {
            throw new Exception('Invalid header encoding');
        }

        if (\is_null($payload)) {
            throw new Exception('Invalid payload encoding');
        }

        if (empty($headers['alg'])) {
            throw new Exception('Empty algorithm');
        }

        if (empty(self::ALGORITHMS[$headers['alg']])) {
            throw new Exception('Algorithm not supported');
        }

        if (!\hash_equals($algorithm, $headers['alg'])) {
            throw new Exception('Incorrect key for this algorithm');
        }

        if (\in_array($headers['alg'], ['ES256', 'ES256K', 'ES384'], true)) {
            // OpenSSL expects an ASN.1 DER sequence for ES256/ES256K/ES384 signatures
            $signature = self::signatureToDER($signature);
        }

        if (!self::verify("{$headers64}.{$payload64}", $signature, $key, $headers['alg'])) {
            throw new Exception('Invalid signature');
        }

        // Check the nbf if it is defined. This is the time that the token can actually be used. If it's not yet that time, abort.
        if (isset($payload['nbf']) && \floor($payload['nbf']) > $timestamp) {
            throw new Exception('Cannot handle token with nbf prior to ' . \date(DATE_ATOM, (int) $payload['nbf']));
        }

        // Check that this token has been created before 'now'.
        // This prevents using tokens that have been created for later use (and haven't correctly used the nbf claim).
        if (!isset($payload['nbf']) && isset($payload['iat']) && floor($payload['iat']) > $timestamp) {
            throw new Exception('Cannot handle token with iat prior to ' . \date(DATE_ATOM, (int)$payload['iat']));
        }

        // Check if this token has expired.
        if (isset($payload['exp']) && $timestamp >= $payload['exp']) {
            throw new Exception('Expired token');
        }

        return $payload;
    }

    /**
     * Encode a payload array as a JWT, signed with the given key, key ID, and algorithm.
     *
     * @param array<string, mixed> $payload
     *
     * @throws \Exception
     */
    public static function encode(
        array $payload,
        string $key,
        string $algorithm,
        string $keyId = null
    ): string {
        $header = [
            'typ' => 'JWT',
            'alg' => $algorithm,
        ];

        if (!\is_null($keyId)) {
            $header['kid'] = $keyId;
        }

        $header = \json_encode($header, \JSON_UNESCAPED_SLASHES);
        $payload = \json_encode($payload, \JSON_UNESCAPED_SLASHES);

        $segments = [];
        $segments[] = self::safeBase64Encode($header);
        $segments[] = self::safeBase64Encode($payload);

        $signingMaterial = \implode('.', $segments);

        $signature = self::sign($signingMaterial, $key, $algorithm);

        $segments[] = self::safeBase64Encode($signature);

        return \implode('.', $segments);
    }

    /**
     * @throws \Exception
     */
    private static function sign(string $data, string $key, string $alg): string
    {
        if (empty(self::ALGORITHMS[$alg])) {
            throw new \Exception('Algorithm not supported');
        }

        [$function, $algorithm] = self::ALGORITHMS[$alg];

        switch ($function) {
            case 'openssl':
                $signature = '';

                $success = \openssl_sign($data, $signature, $key, $algorithm);

                if (!$success) {
                    throw new \Exception('OpenSSL sign failed for JWT');
                }

                switch ($alg) {
                    case 'ES256':
                    case 'ES256K':
                        $signature = self::signatureFromDER($signature, 256);
                        break;
                    case 'ES384':
                        $signature = self::signatureFromDER($signature, 384);
                        break;
                    default:
                        break;
                }

                return $signature;
            case 'hash_hmac':
                return \hash_hmac($algorithm, $data, $key, true);
            default:
                throw new \Exception('Algorithm not supported');
        }
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $msg The original message (header and body)
     * @param string $signature The original signature
     * @param string $key For Ed*, ES*, HS*, a string key works. for RS*, must be an instance of OpenSSLAsymmetricKey
     * @param string $algorithm
     * @return bool
     * @throws Exception
     */
    private static function verify(
        string $msg,
        string $signature,
        string $key,
        string $algorithm
    ): bool {
        [$function, $algorithm] = static::ALGORITHMS[$algorithm];

        if (\str_starts_with($algorithm, 'RS')) {
            $key = \openssl_pkey_get_private($key);
        }

        switch ($function) {
            case 'openssl':
                $success = \openssl_verify($msg, $signature, $key, $algorithm);
                if ($success) {
                    return true;
                }
                return false;
            case 'hash_hmac':
                $hash = \hash_hmac($algorithm, $msg, $key, true);
                return \hash_equals($hash, $signature);
            default:
                throw new \Exception('Algorithm not supported');
        }
    }

    /**
     * Encodes signature from a DER object.
     *
     * @param string $der binary signature in DER format
     * @param int $keySize the number of bits in the key
     */
    private static function signatureFromDER(string $der, int $keySize): string
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        [$offset, $_] = self::readDER($der);
        [$offset, $r] = self::readDER($der, $offset);
        [$_, $s] = self::readDER($der, $offset);

        // Convert r-value and s-value from signed two's compliment to unsigned big-endian integers
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Pad out r and s so that they are $keySize bits long
        $r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private static function signatureToDER(string $sig): string
    {
        // Separate the signature into r-value and s-value
        $length = max(1, (int) (\strlen($sig) / 2));
        list($r, $s) = \str_split($sig, $length);

        // Trim leading zeros
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            0x10,
            self::encodeDER(0x02, $r) .
            self::encodeDER(0x02, $s)
        );
    }

    /**
     * Reads binary DER-encoded data and decodes into a single object
     *
     * @param int $offset
     * to decode
     * @return array{int, string|null}
     */
    private static function readDER(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = \strlen($der);
        $constructed = (\ord($der[$pos]) >> 5) & 0x01;
        $type = \ord($der[$pos++]) & 0x1F;

        // Length
        $len = \ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1F;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | \ord($der[$pos++]);
            }
        }

        // Value
        if ($type === 0x03) {
            $pos++; // Skip the first contents octet (padding indicator)
            $data = \substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = \substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return [$pos, $data];
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     *
     * @return  string  the encoded object
     */
    private static function encodeDER(int $type, string $value): string
    {
        $tagHeader = 0;

        if ($type === 0x10) {
            $tagHeader |= 0x20;
        }

        // Type
        $der = \chr($tagHeader | $type);

        // Length
        $der .= \chr(\strlen($value));

        return $der . $value;
    }

    private static function safeBase64Decode(string $input): string
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }

        return \base64_decode(\str_replace(['-', '_'], ['+', '/'], $input));
    }

    /**
     * Encode a string with URL-safe Base64.
     */
    private static function safeBase64Encode(string $input): string
    {
        return \str_replace(['+', '/', '='], ['-', '_', ''], \base64_encode($input));
    }
}
