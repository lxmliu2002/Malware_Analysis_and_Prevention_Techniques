rule lab13exe
{
strings:
	$string1 = "ole32.vd"
	$string2 = "OLEAUTLA" 
	$string3 = "_getmas"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3
}
