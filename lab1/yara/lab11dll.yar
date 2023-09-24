rule lab11dll
{
strings:
	$string1 = "sleep"
	$string2 = "exec" 
	$string3 = "CreateProcessA"
condition:
	filesize < 10MB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and $string1 and $string2 and $string3
}
