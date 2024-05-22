rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware behavior with multiple indicators"

    strings:
        $ransom_note1 = "Your files have been encrypted" ascii wide
        $ransom_note2 = "All your files are encrypted" ascii wide
        $ransom_note3 = "Decrypt your files" ascii wide
        $encrypted_extension1 = ".locked" ascii wide
        $encrypted_extension2 = ".crypt" ascii wide
        $encrypted_extension3 = ".enc" ascii wide
    condition:
        any of ($ransom_note*, $encrypted_extension*)
}

rule Trojan_Generic {
    meta:
        description = "Detects generic Trojan behavior with multiple indicators"
    strings:
        $trojan_string1 = "Net connection reset"
        $trojan_string2 = "Usage: %s [options] [http://]hostname[:port]/path"
    condition:
        any of them
}

rule Spyware_Generic {
    meta:
        description = "Detects generic spyware behavior with multiple indicators"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/spyware-research"
    strings:
        $spyware_string1 = "CaptureScreenshot" ascii
        $spyware_string2 = "KeyLogger" ascii
        $spyware_string3 = "StealPassword" ascii
        $trojan_string2 = "Usage: %s [options] [http://]hostname[:port]/path"
    
      
    condition:
        any of them
}

rule Worm_Generic {
    meta:
        description = "Detects generic worm behavior with multiple indicators"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/worm-research"
    strings:
        $worm_string1 = "SpreadToNetwork" ascii
        $worm_string2 = "CopyToUSB" ascii
        $worm_string3 = "NetworkPropagation" ascii
        $worm_string4 = "EmailSpread" ascii
    condition:
        any of them
}

rule ExploitKit_Generic {
    meta:
        description = "Detects generic exploit kit behavior with multiple indicators"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/exploitkit-research"
    strings:
        $exploitkit_string1 = "Exploit" ascii
        $exploitkit_string2 = "Shellcode" ascii
        $exploitkit_string3 = "ExploitPayload" ascii
        $exploitkit_string4 = "ExploitKit" ascii
    condition:
        any of them
}

rule Packed_Malware_Generic {
    meta:
        description = "Detects common packed malware with multiple packer identifiers"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/packer-research"
    strings:
        $packer_string1 = "UPX0" ascii
        $packer_string4 = "PECompact" ascii
        $packer_string5 = "ASPack" ascii
    condition:
        any of them
}

rule KnownMalwareFamily {
    meta:
        description = "Detects a specific known malware family with detailed signatures"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/knownmalware-research"
    strings:
        $malware_signature1 = { E8 00 00 00 00 5D C3 }
        $malware_signature2 = { 6A 40 68 00 30 00 00 }
        $malware_signature3 = { 60 89 E5 31 C0 64 8B 50 30 }
        $malware_signature4 = { 68 8D 4C 24 04 89 E1 6A 10 }
    condition:
        any of them
}

rule Obfuscated_Malware_Generic {
    meta:
        description = "Detects generic obfuscated malware with multiple indicators"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/obfuscatedmalware-research"
    strings:
        $obfuscation_string1 = "Function1" ascii
        $obfuscation_string2 = "Function2" ascii
        $obfuscation_string3 = "EncodedPayload" ascii
        $obfuscation_string4 = "ObfuscatedCode" ascii
        $obfuscation_string5 = { 8B 45 0C 89 45 FC 8B 45 10 }
    condition:
        any of them
}

rule Polymorphic_Malware_Generic {
    meta:
        description = "Detects generic polymorphic malware with multiple indicators"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/polymorphicmalware-research"
    strings:
        $polymorphic_string1 = "PolymorphicEngine" ascii
        $polymorphic_string2 = "CodeMutation" ascii
        $polymorphic_string3 = "VariableEncryption" ascii
    condition:
        any of them
}

rule Fileless_Malware_Generic {
    meta:
        description = "Detects generic fileless malware with memory patterns"
        author = "Your Name"
        date = "2024-05-21"
        reference = "https://example.com/filelessmalware-research"
    strings:
        $fileless_string1 = "Powershell" ascii
        $fileless_string2 = "Invoke-Mimikatz" ascii
        $fileless_string3 = "ReflectiveLoader" ascii
    condition:
        any of them
}
