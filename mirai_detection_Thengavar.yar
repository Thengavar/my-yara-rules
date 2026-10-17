rule Linux_Mirai_Mutation_Detected_Thengavar {
    meta:
        description = "Detects Mirai botnets and their mutations based on patterns"
        author = "Thengavar"
        date = "2026-10-17"
        severity = "High"
	yarahub_reference_md5 = "cb342cf20ae22085a14d2da8446f073c"
	yarahub_license = "CC0 1.0"
	yarahub_uuid = "e903262e-a32b-4165-95c6-58f65e1b7e1b"
	yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"


    strings:
        $attack_1 = "attack_udp_generic" ascii
        $attack_2 = "attack_tcp_syn" ascii
        $attack_3 = "attack_http_httpflooding" ascii

        $mirai_port = "\\xbb\\xc5"

        $login_1 = "admin:admin" ascii
        $login_2 = "root:12345" ascii
        $login_3 = "telnet" ascii

    condition:
        uint32(0) == 0x464c457f and 
        ((2 of ($attack_*)) or ($mirai_port and 1 of ($login_*)))
}
