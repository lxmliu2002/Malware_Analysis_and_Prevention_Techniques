rule lab1201exe{
strings:
	$dll1 = "Lab12-01.dll"
	$string1 = "GetModuleBaseNameA"
    $dll2 = "psapi.dll"
    $string2 = "EnumProcessModules"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}


rule lab1202exe{
strings:
    $reg1 = "AAAqAAApAAAsAAArAAAuAAAtAAAwAAAvAAAyAAAxAAA"
	$dll1 = "spoolvxx32.dll"
	$exe1 = "svchost.exe"
    $string = "NtUnmapViewOfSection"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and 3 of them
}


rule lab1203exe{
strings:
	$log = "practicalmalwareanalysis.logl"
	$func = "VirtualAlloc"
    $string1 = "TerminateProcess"
    $string2 = "[Window:"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and 2 of them
}

rule lab1204exe{
strings:
    $log = "http://www.practicalmalwareanalysis.com//updater.exe"
	$exe1 = "wupdmgrd.exe"
	$exe2  = "winup.exe"
    $string1 = "<SHIFT>"
    $string2 = "%s%s"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and 2 of them
}
