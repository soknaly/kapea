# Placeholder YARA rule package for local development.
# Replace with validated production rules before deploying.

rule Kapea_Eicar_Test
{
    meta:
        description = "Detects the EICAR antivirus test string"
        author = "kapea"
        severity = "malicious"
        version = "1"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
