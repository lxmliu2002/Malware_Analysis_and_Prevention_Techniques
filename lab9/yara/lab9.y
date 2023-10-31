rule lab0901exe
{
strings:
 $string1 = "CMD"
 $string2 = "SLEEP"
 $string3 = "DOWNLOAD"
 $string4 = "NOTHING"
condition:
 filesize<100KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab0902exe
{
strings:
 $string1 = "C++"
 $string2 = "R6019"
 $string3 = "R6009"
 $string4 = "Socket"
condition:
 filesize<100KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab0903exe
{
strings:
 $string1 = "DLL3.dll" 
 $string2 = "DLL3Print"
condition:
 filesize<50KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}


