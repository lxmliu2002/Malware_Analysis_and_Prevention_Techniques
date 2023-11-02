rule lab1101exe{
strings:
	$string1 = "UN %s DM %s PW %s OLD %s" nocase
	$reg = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    $dll1 = "MSGina.dll"
    $dll2 = "GinaDLL"
condition:
    filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 1 of them
}


rule lab1102dll{
strings:
    $reg1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
	$dll1 = "spoolvxx32.dll"
	$exe1 = "THEBAT.EXE"
    $exe2 = "OUTLOOK.EXE"
	$exe3 = "MSIMN.EXE"
condition:
    filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 3 of them
}

rule lab1102ini{
strings:
    $string1 = "BNL"
condition:
    filesize < 100KB and 1 of them
}


rule lab1103exe{
strings:
	$dll1 = "C:\\WINDOWS\\System32\\inet_epar32.dll"
	$dll2 = "Lab11-03.dll"
    $exe1 = "cisvc.exe"
    $string1 = "net start cisvc"
    $func1 = "zzz69806582"
condition:
    filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 3 of them
}

rule lab1103dll{
strings:
    $dll1 = "C:\\WINDOWS\\System32\\kernel64x.dll"
	$func1 = "VirtualAlloc"
    $func2 = "RtlUnwind"
	$sys1  = "Lab10-03.sys"
    $string1 = "<SHIFT>"
condition:
    filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C))==0x00004550 and 3 of them
}
