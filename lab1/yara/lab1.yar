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
rule lab11dll
{
strings:
	$string1 = "sleep"
	$string2 = "exec" 
	$string3 = "CreateProcessA"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3
}
rule lab12exe
{
strings:
	$string1 = "HGL345"
	$string2 = "MalService" 
	$location = {68 74 74 70 3A 2F 2F 77 FF B7 BF DD 00 2E 6D 1E 77 61 72 65 61 6E 07 79 73 69 73 62 6F 6F 6B 2E 63 6F FF DB DB 6F 6D}
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $location
}
rule lab13exe
{
strings:
	$string1 = "ole32.vd"
	$string2 = "OLEAUTLA" 
	$string3 = "_getmas"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3
}
rule lab14exe
{
strings:
	$string1 = "LoadResource"
	$string2 = "FindResource" 
	$string3 = "SizeofResource"
	$string4 = "\\system32\\wupdmgr.exe"
	$string5 = "http://www.practicalmalwareanalysis.com/updater.exe"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3 and $string4 and $string5
}