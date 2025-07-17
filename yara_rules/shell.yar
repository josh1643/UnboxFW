rule BusyBoxShell
{
    strings:
        $bb = "/bin/sh"
    condition:
        $bb
}
