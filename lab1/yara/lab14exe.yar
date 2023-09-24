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
