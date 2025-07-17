rule HardcodedPassword
{
    strings:
        $1 = "root:root"
        $2 = "admin:admin"
        $3 = "password123"
    condition:
        any of them
}
