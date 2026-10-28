import "elf"

rule MassiveMiraihunt_IoT_Botnet_Gen {
    meta:
        description = "Generische Massive-Hunting-Regel fuer Mirai-Botnets (ELF MIPS/ARM)"
        author = "Thengavar"
        date = "2026-10-28"
        malware_family = "Mirai / Gafgyt"
        tlp = "TLP:WHITE"
        confidence = "High"

    strings:
        $hex_mips_anchor = { 24 02 00 22 24 05 00 00 02 40 90 25 }
        $hex_arm_anchor  = { E2 4B 00 22 E2 8A 00 01 }
        $hex_table_init  = { 3C 02 00 04 24 04 00 08 }

    condition:
        uint16(0) == 0x457f and filesize < 300KB and 
        (1 of ($hex_*))
}
