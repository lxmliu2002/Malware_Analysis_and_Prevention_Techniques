rule lab1301exe{
strings:
	$string1 = "Mozilla/4.0"
	$string2 = "https://%s/%s/"
	$string3 = "CloseHandle"
	$string4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and 3 of them
}


rule lab1302exe{
strings:
    $string1 = "56@"
    $string2 = "temp%08x"
    $string3 = "MultiByteToWideChar"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}


rule lab1303exe{
strings:
	$string1 = "CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	$string2 = "ijklmnopqrstuvwx"
	$string3 = "WriteConsole"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and 2 of them
}
