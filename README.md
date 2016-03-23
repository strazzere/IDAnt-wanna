# IDAnt-wanna
ELF header abuse

## Archive of blog entry
Originally posted at https://www.sentinelone.com/blog/breaking-and-evading/

The focus of any malware research is on anticipating where an attack may go, or where it’s
already been in order to develop and implement new prevention techniques.  While reverse 
engineering some recent Linux malware samples, I found an interesting and novel technique 
being used that’s important to share with the broader community. A malicious actor had logged
into a honeypot and attempted to download a file I hadn’t seen before. Loading the file into 
IDA Pro I was prompted by a “SHT table size or offset is invalid. Continue?” message - nothing
to worry about as this is normal for every stripped executable. However, after continuing through
this message I was prompted by a new warning I’d not seen before;

![IDA Pro loading error](/resources/ida_error.png?raw=true)

This caused the the ELF loader to fail in IDA Pro - preventing me from loading the binary for
analysis. Opening up the file in 010Editor using the ELFTemplate it was quite easy to see what
had happened;

![010Editor ELF Template](/resources/010editor.png?raw=true)

One of the program headers was pointing outside of the actual file. This is easy to fix, 
simply nulling this section out allowed IDA Pro to load the sample. Interestingly enough, 
it turned out this was an invalid binary and the section was misaligned only because the 
file was truncated. However, this error message lead me down the path to try and reconstruct
this error - and it was simple to do. The steps were relatively easy to reproduce using the 
hex editor;

 - Strip all sections from the ELF header
 - Find a program header which is not required by the ELF file for loading
 - Make this program header have the offset for this section pointing outside of the file

As long as the rest of the section headers are not found - IDA Pro will fail to load. After
scripting this process, I decided to test a few scenarios with other disassemblers and
debuggers. Radare (r2), Hopper and lldb handled the binary perfectly fine - however GDB
failed to understand the file format;

![GDB issues](/resources/gdb.png?raw=true)

Trying to take things a bit further I wanted to see if this would work as not only an
anti-disassembly technique, but also an anti-analysis or obfuscation technique. The idea 
was that if I was so easily able to find this issue with a few disassemblers, it would be 
likely that some anti-virus applications may have also implemented the same issue in their 
parsing engines. From here I grabbed a relatively well detected malware sample from the 
Linux/XorDDos family;

![XorDDOS Normal Detections](/resources/vt_normal.png?raw=true)
https://www.virustotal.com/en/file/0a9e6adcd53be776568f46c3f98e27b6869f63f9c356468f0d19f46be151c01a/analysis/

While not a seemingly advanced technique, I did not anticipate many engines to be fooled by
this - I assumed most of the engines would simply revert to a more simple type of scanning 
and still catch the older malware. However, after modifying the sample to have a bad program 
header, I reuploaded and to my surprise the detects dropped by a third;

![XorDDOS Nerfed Detections](/resources/vt_nerfed.png?raw=true)
https://www.virustotal.com/en/file/7495e5a6f81f0e59cbbc478e05f575f23cadb4b07e12b0b44b760d1c93e7adf7/analysis/

9 different engines (Two appear to be owned by the same company? So I hesitate to say 10) failed 
to detect the same malware, they just recently detected. This was interesting to me, as I’m r
elatively new to the Linux side of malware, I would have assumed that these engines would have 
easily detected the malware and a simple change like this would not be such a simple evasion technique.

It seemed almost too easy to beat the disassemblers and engines - so I wanted to look across a
large corpus of samples and see if anyone else has stumbled upon and implemented this technique.
Using the rather simple YARA rule below, I was able to find over 6,000 samples which are currently
utilizing this exact technique. Luckily, almost every single one of these samples was just a 
commercial Android packer attempting to protect it’s own code.

While we have yet to see any malicious actors use this technique in the wild, there are likely 
many other similar tricks being used in the wild. This is a good start at looking to see how ELF 
files might be abused to hide from analysis, and hopefully with the release of these scripts, people
will be able to monitor for this technique being used and other similar ones in the future.

Prior to publishing this article, I’ve notified Hex-Rays and the 10 engines which failed to detect the slightly modified malware. The script for producing and fixing these modified binaries can be found on github here. 

###Yara Rule:

```
import "elf"

rule IDAnt_wanna : antidisassemble antianalysis {
	meta:
		author = "Tim 'diff' Strazzere <diff@sentinelone.com> <strazz@gmail.com>"
		filetype = "elf"
		description = "Detect a misaligned program header which causes some analysis engines to fail"
		version = "1.0"
		date = "2015-12"
	condition:
		for any i in (0..elf.number_of_segments - 1) : (elf.segments[i].offset >= filesize) and
		elf.number_of_sections == 0 and
		elf.sh_entry_size == 0
}
```

### Disclaimer

This blog and code are meant for education and research purposes only. Do as you please with it,
but accept any and all responsibility for your actions. The tools were created specifically to 
assist in malware reversing and analysis - be careful.

### License


    Copyright 2015 Tim 'diff' Strazzere <diff@sentinelone.com> <strazz@gmail.com>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
