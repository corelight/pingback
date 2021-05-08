# Pingback C2 Detection

A Zeek package and Suricata rules for detection of ICMP ping tunnels created by the Pingback C2 tool.  
Accompanying blog post: https://corelight.blog/2021/05/07/pingback-icmp-tunneling-malware/  

## Installation

The easiest way to install this package is through [zkg](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html):

```zkg install corelight/pingback```

## Usage

Use [this example PCAP](https://github.com/SpiderLabs/IOCs-IDPS/tree/master/Pingback) and you can follow along below:

```
$ ls
Pingback_ICMP.pcapng

$ zeek -Cr Pingback_ICMP.pcapng pingback

$ cat notice.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2021-05-07-14-43-48
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	interval	string	string	string	double	double
1619505583.332605	CH7l4D48kbE3nWo7M7	192.168.38.131	8	192.168.38.172	0	-	-	-	icmp	Pingback::Pingback_Tunnel	An ICMP ping request message may have been Pingback C2 ref:trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/	seq=53764 , |payload|=788 , icmp_info=[v6=F, itype=8, icode=0, len=788, ttl=64] , first 20 bytes of ICMP payload=shell\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00	192.168.38.131	192.168.38.172	0	-	-	Notice::ACTION_LOG	3600.000000	-	-	-	-	-
1619505583.333021	CH7l4D48kbE3nWo7M7	192.168.38.131	8	192.168.38.172	0	-	-	-	icmp	Pingback::Pingback_Tunnel	An ICMP ping reply message may have been Pingback C2 ref:trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/	seq=53764 , |payload|=788 , icmp_info=[v6=F, itype=0, icode=0, len=788, ttl=128] , first 20 bytes of ICMP payload=shell\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00	192.168.38.131	192.168.38.172	0	-	-	Notice::ACTION_LOG	3600.000000	-	-	-	-	-
#close	2021-05-07-14-43-48
```

## Additional References

- https://www.bleepingcomputer.com/news/security/new-windows-pingback-malware-uses-icmp-for-covert-communication/
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/backdoor-at-the-end-of-the-icmp-tunnel/
- https://github.com/SpiderLabs/pingback
- https://www.virustotal.com/gui/file/e50943d9f361830502dcfdb00971cbee76877aa73665245427d817047523667f/detection

## License

Copyright (c) 2021, Corelight, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

(1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

(3) Neither the name of Corelight nor the names of any contributors
    may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
