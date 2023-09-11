rule lab11exe
{
strings:
	$string1 = "Lab01-01.dll"
	$string2 = "kerne132.dll"
	$string3 = "C:\\windows\\system32\\kerne132.dll"
	$string4 = "FindFirstFile"
	$string5 = "FindNextFile"
	$string6 = "CopyFile"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3 and $string4 and $string5 and $string6
}
