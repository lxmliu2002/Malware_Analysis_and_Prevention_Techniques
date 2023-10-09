rule lab0601
{
strings:
	$string1 = "Error 1.1: No Internet" 
	$string2 = "Success: Internet Connection"
	$string3 = "InternetGetConnectedState"
condition:
	filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}
rule lab0602
{
strings:
	$string1 = "http://www.practicalmalwareanalysis.com/cc.htm" 
	$string2 = "Error 2.3: Fail to get command"
	$string3 = "Internet Explorer 7.5/pma"
condition:
	filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}
rule lab0603
{
strings:
	$string1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" 
	$string2 = "C:\\Temp\\cc.exe"
	$string3 = "C:\\Temp"
condition:
	filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}
rule lab0604
{
strings:
	$string1 = "Success: Parsed command is %c" 
	$string2 = "DDDDDDDDDDDDDD"
condition:
	filesize < 100KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}