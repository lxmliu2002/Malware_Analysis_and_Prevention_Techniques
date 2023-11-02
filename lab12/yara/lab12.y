rule lab0701exe
{
strings:
 $string1 = "HGL345" 
 $string2 = "http://www.malwareanalysisbook.com"
 $string3 = "Internet Explorer 8.0"
condition:
 filesize<50KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab0702exe
{
strings:
 $string1 = "_controlfp"
 $string2="__setusermatherr"
 $fun1 = "OleUninitialize"
 $fun2 = "CoCreateInstance" 
 $fun3= "OleInitialize"
 $dll1="MSVCRT.dll" nocase 
 $dll2="OLEAUT32.dll" nocase
 $dll3="ole32.dll" nocase
condition:
 filesize<100KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab0703exe
{
strings:
 $string1 = "kerne132.dll" 
 $string2 = "Lab07-03.dll"
condition:
 filesize<50KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}

rule lab0703dll
{
strings:
 $string1 = "127.26.152.13" 
 $string2 = "_adjust_fdiv"
condition:
 filesize<200KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}
