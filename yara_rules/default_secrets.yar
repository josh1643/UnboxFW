rule PrivateKey
{
    strings:
        $pem_start = "-----BEGIN PRIVATE KEY-----"
    condition:
        $pem_start
}
