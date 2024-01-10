<?php

namespace Utopia\Tests\JWT;

use PHPUnit\Framework\TestCase;
use Utopia\JWT\JWT;

class JWTTest extends TestCase
{
    public function testEncodeRS256(): void
    {
        $payload = [
            'foo' => 'bar',
        ];

        $key = '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnSei4riGJnjm8xbpx4g9veiuXTlE4i7JNcT475Q28PKyQaQ7
TTl1/ZR6yHOqRvXS36baH/+iUPslg+jctI6k8YulQcy72rCWamzDU13NEkg+xC+m
zlxzGxXYiaTEpG3drKbiOnEXeWqtJXtez9cLkhVC42xEYJUFe5wYoGldTkSdaSFE
gpJ0Nw5KA7qUmf79qM3U6+4rbgH8VVltzf3nHtvqXTtoSpAFgr6NgmH2ZzEUe/LO
emgUlejtVaFb2QaxqcFsDHlotew/XBQEMKOwMnx0J8Ffeh4KiFbA9/fvtc9oO5y6
3RfZ2ZCRiDEvBsDLr8EKk782tQgneSUq4c1+/wIDAQABAoIBAQCM+c9unqUIwhA7
JOTWL2tjfuVbj1IxrFKnP2koUcbvYmdx5wejgNZNgfKa+tdXDJH8O0sUxVcwWfsP
V8cU2ZkxbVnzqtshlKN6GNMnZ8/chJ55k12JZPmE5JX486vK7RucE6CBWI38RyvH
oeItg/VHOHdmV+sG0Oe4OREGZT5kRFI+1CnclMPhBBKw+FBV3jRmyBrjbH2b+Wv2
7hS1jUYAiylq/xR6V31yhg7yTgE6e+epsDqcNxPWp8o9igYI3Jk0jzrPC2hVecGv
3nqgiJR+CRmjR7EzdPi77wpW+IF0gQC6J52K9qpbZG7Oo3GSpxVICFaKZnYZDxHB
rCC6WzAhAoGBAOPWhc06Vx83mGARX/+XZwhhnT0AO3sQlaGFSvLUnIve47nXCxL0
fWP9attFKcRaLEdzZ6bZxcMV7GBXAryRPvRe3v7W4LjE4sbP6vqb81K6+k8zD1YG
iMdV6to2kfwENyJEG0RMQX/JO2jdHrytnM+ukGcfafdBbwhlJPqRxasHAoGBALCU
fJS5UtpZuq5dN5esnciCfKiyOvHjn7hw9pNpwIwgGSup9FA+doGaNpNmLHL7llF/
nO2xih2sj4TzUHGUolNO3wzenns/m99J7YtZQy0llb2u7BJEx8PTDPR/h1caJxPZ
s8ABhY2RgCU7dPYob+sLHq/Tn0NfZ9nqwW4gcfZJAoGAHXBWkZH8N9hjI+aa1Nen
RHn4ay1ggiI+c0RZzs6R+7CtFBIpKCXXHdhcukBRiUFtfz32IqT43KA0jq4veFX8
IG8xuRPirX0jIDU1U3RbGFF4jks2rBLkEX2UfuWWL04MIa1TKJwBypUhzAbmNdLo
9BzGI8z3UC9wPVF0WbwEInkCgYEAp9hM3zWVatX12/3hdPvwcwKNqfDYlMqwLKq7
xv2zt75fDqEbCReGn8TNcaiiQZ2hkdBCg7HJvlEjjtWVNpF5BsUmwd3uOOsKp+Fm
uZlcgFKElmvqG6djV2GKo/GA3SuPz4+VC8Kmhx2x+DIfCEkBsSK9xZXbgjfyyDIc
MSkICnkCgYA3FedyakWHxTUf2/Fk4SgR+w5qAZtxBAEorV0AkKUv1dk2GpVYvJ8C
L6RiNUWKzGsDzYzSIVa7aD/3TjuAs6CUgapsJn5+Zm4NMlwUYAkJSgL1oJbYNNQ6
1yonxiwj/HjVI3oCShECsPLNh58E28s0o6mIAh1lisvDRH/uAk2RIA==
-----END RSA PRIVATE KEY-----';

        $algorithm = 'RS256';

        $jwt = JWT::encode($payload, $key, $algorithm);

        $expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.Yx-K0makmzYNBSoxejqWROYDXrap8x-7IO_Ik_CeXfHM38a6oXzZ9adm83rFmjJL5WFrRyz5mpGpTKd7hmlA9320bgLXSE6K5ByBBh9V4b3g-iUAmokRzfp_OLFeghsJ7B4UB5Vcjlx9b0DHsNSaycsIriK08Pm7ZtdAdetfIfnsMhye6GXECkFIex4bNd6hrF9e96Gq1ePn_ofjCjUNhQNAE_IPZOdadKvoRfJd_0VLCKYxpW4JheXTI3e7lh5_PnUWfnRN3srDEJk-nROtknuJV1FFUVDJG0Pr0BcI-gmJhHIOmYpO8Zt6jdeqfIPjPawQXROjlGeN_WefILlwMQ';

        $this->assertEquals($expected, $jwt);

        $decoded = JWT::decode($jwt, $key, $algorithm);

        $this->assertEquals($payload, $decoded);
    }

    public function testEncodeES256(): void
    {
        $payload = [
            'foo' => 'bar',
        ];

        $key = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFw1p6REUn7YKO448et37rdWNIehX12Z8xHhG1KUbYBfoAoGCCqGSM49
AwEHoUQDQgAE+yv4CsIwq3K/wSthh+qBuNy5flmEa+nbnErOCEIZKLIm6HO4t3vp
a+92oL+tG28OowSTuc2DBw4KRmJg6JlpDg==
-----END EC PRIVATE KEY-----';

        $keyId = 'testId';

        $algorithm = 'ES256';

        $jwt = JWT::encode(
            $payload,
            $key,
            $algorithm,
            $keyId,
        );

        //$expected = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6InRlc3RJZCJ9.eyJmb28iOiJiYXIifQ.7Jmbs3NHeG8KDBJkkf6Cx5JJFo8w5Ws2FmJevXTu3jXj9k_vpCAfVlFjI_ZyfWoxI_bjgdO89QkmcCkxjh3lDQ';

        \var_dump($jwt);

        //$this->assertEquals($expected, $jwt);
    }
}