rule lab4
{
strings:
	$string1 = "socket() GetLastError reports %d" 
	$string2 = "WSAStartup() error: %d"
	$string3 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
	$string4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
	$string5 = "xkey.dll"
condition:
	filesize<150KB and uint16(0)==0x5A4D and uint16(uint16(0x3C))==0x00004550 and all of them
}
