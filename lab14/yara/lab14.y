rule lab1401exe{
strings:
	$string1 = "http://www.practicalmalwareanalysis.com/%s/%c.png"
	$string2 = "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c"
	$string3 = "%s-%s"
	$string4 = "I.@"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}


rule lab1402exe{
strings:
    $string1 = "WXYZlabcd3fghijko12e456789ABCDEFGHIJKL+/MNOPQRSTUVmn0pqrstuvwxyz"
    $string2 = "COMSPEC"
    $string3 = "http://127.0.0.1/tenfour.html"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}


rule lab1403exe{
strings:
	$string1 = "http://www.practicalmalwareanalysis.com/start.htm"
	$string2 = "autobat.exe"
	$string3 = "Accept-Language: en-US"
condition:
    filesize < 200KB and uint16(0) == 0x5A4D and uint16(uint16(0x3C)) == 0x00004550 and all of them
}
