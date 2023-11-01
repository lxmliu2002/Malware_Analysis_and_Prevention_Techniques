rule lab1001exe{
strings:
    $string1 = "REGWRITERAPP" nocase
    $sys1 = "C:\\Windows\\System32\\Lab10-01.sys"
    $func1 = "GetLastActivePopup"
    $func2 = "OpenServiceA"
    $func3 = "StartServiceA"
    $func4 = "OpenSCManagerA"
    $func5 = "GetCurrentProcess"
    $func6 = "GetOEMCP"
    $string2 = "RegWriterApp Version 1.0"
condition:
    filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 5 of them
}

rule lab1001sys{
strings:
    $string1 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
    $string2 = "6.1.7600.16385"
    $string3 = "c:\\winddk\\7600.16385.1\\src\\general\\regwriter\\wdm\\sys\\objfre_wxp_x86\\i386\\sioctl.pdb"
    $string4 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft"
    $string5 = "\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
condition:
    filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 1 of them
}

rule lab1002exe{
strings:
    $string1 = "NtQueryDirectoryFile"
    $string2 = "KeServiceDescriptorTable"
    $string3 = "c:\\winddk\\7600.16385.1\\src\\general\\rootkit\\wdm\\sys\\objfre_wxp_x86\\i386\\sioctl.pdb"
    $string4 = "C:\\Windows\\System32\\Mlwx486.sys"
    $string5 = "486 WS Driver"
condition:
    filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 5 of them
}


rule lab1003exe{
strings:
    $string1 = "C:\\Windows\\System32\\Lab10-03.sys"
    $string2 = "Process Helper"
    $string3 = "\\.\\ProcHelper"
    $http = "http://www.malwareanalysisbook.com/ad.html"
    $func1 = "GetOEMCP"
    $func2 = "GetCurrentProcess"
    $dll1 = "OLEAUT32.dll"
    $dll2 = "ole32.dll"
condition:
    filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab1003sys{
strings:
    $string1 = "ntoskrnl.exe"
    $string2 = "\\DosDevices\\ProcHelper"
    $sys1  = "Lab10-03.sys"
    $func1 = "IoCreateDevice"
    $func2 = "IoCreateSymbolicLink"
    $func3 = "IoGetCurrentProcess"
    $func4 = "RtlInitUnicodeString"
    $func5 = "IoDeleteSymbolicLink"
condition:
    filesize < 50KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 4 of them
}
