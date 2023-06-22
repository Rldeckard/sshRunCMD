from paramiko import SSHClient
from paramiko import AutoAddPolicy
from paramiko import ssh_exception
import socket #only needed to handle socket timeout. Sockets are handled through paramiko
import time
from rsa import decrypt, PrivateKey
from sys import exit
from pythonping import ping
from threading import Thread
from multiprocessing import Process, Lock, log_to_stderr, SUBDEBUG
import yaml
from yaml.loader import SafeLoader
from getpass import getpass
from credentials import CredFile
from base64 import b64decode

privateKey = PrivateKey.load_pkcs1("[PRIVATE_KEY]") #need private key from rsa to decrypt cred file. Can be done differently
coreIP = "" #need an IP to validate AD credentials. I use a switch core ip. If that connection fails the program exits.

def runScript(channel, script):
    terminal = ''
    count = 0
    channel.send(f'terminal length 0\n') #turns off paging to get full command output
    for code in script:
        channel.send(f'{code}\n')
        time.sleep(.2)
        out = channel.recv(9999)
        readOut = out.decode('ascii')
        while '#' not in readOut.splitlines()[-1]: #verify command is finshed before running the next
            time.sleep(.2)
            out += channel.recv(9999)
            readOut = out.decode('ascii')
            if count >= 20:
                break
            ++count
            #print (readOut)
        terminal += readOut #concat output for print to user
        out = '' #clear out previous command output to prepare for new command processing
    channel.send(f'terminal length 32\n') #reenables paging for ux
    return terminal

def getIpList():
    with open('hosts.yaml') as file:
        data = yaml.safe_load(file)
    hostList = data #format data here as needed
    return hostList

#Gets a List of Active Hosts so we're not probing devices that don't exist.
def pingCheck(host, result):
    try:
        responseList = ping(host, timeout=.4, count=1) #returns responseList object
    except RuntimeError: #Host is not an IP Address. Return without result
        return
    response = responseList._responses[0]
    result[host] = str(response) #stays as a dict object unless converted to string manually

#script that is passed to multiprocessing to actually access the device and run the commands
def sshProcess(client, host, scriptArray, credInput):
    authTimeout = 0
    transport = False
    authFailed = False
    if IPaddr == "":
        return
    while not transport: # TODO: Can probably be removed. Originally used to supply unlimited password retries
        try:
            client.connect(IPaddr, username=credInput['username'], password=credInput['password'], timeout=5)
            transport = client.get_transport()
            transport.send_ignore()
        except ssh_exception.NoValidConnectionsError:
            transport = True
            authFailed = True
            print (f"\n{IPaddr} : SSH connection FAILED. Skipping for now.")
        except (TimeoutError, socket.timeout, socket.gaierror):
            transport = True
            authFailed = True
            print (f"\n{IPaddr} : Device timed out. Skipping for now")
        except ssh_exception.AuthenticationException:
            print (f"\n{IPaddr} : Authentication Failed. Using alternate credentials")
            if credInput['username1']:
                try: # we're assuming timeouts have been handled by this point.
                    client.connect(IPaddr, username=credInput['username1'], password=credInput['password1'], timeout=5)
                    transport = client.get_transport()
                    transport.send_ignore()
                except ssh_exception.AuthenticationException:
                    print (f"\n{IPaddr} : Alternate Auth Failed. Please retry")
                    transport = True
                    authFailed = True
            else:
                print (f"\n{IPaddr} : No alt credentials supplied. Moving on.")
                transport = True
                authFailed = True
        if authTimeout >= 10:
            break
        ++authTimeout

    if authFailed == False:
        channel = client.invoke_shell()
        try:
            scriptResults = runScript(channel, scriptArray)
            print (f'\n\n{IPaddr} : Successful Connection\n\n{scriptResults}\n')
        except (Exception, err):
            print(f'\n{IPaddr} : host not responding, {err.message}')

    client.close()

###################################################################

if __name__ == '__main__': #keeps subprocesses from executing recursive code

    pingThread = []
    pingResults = {}
    activeHosts = []
    procs = []
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    massScript = False
    massList = False
    credInput = {}
    scriptArray = []
    hostArray = []
    hostList = getIpList()
    cred = CredFile() 

    
    #Creates a host list and validates it to be able to run commands against all devices
    hostSelect = input("Would you like to define a custom list of IPs? Default is ALL devices[y/n]") or "no"
    if hostSelect.lower() == "y" or hostSelect.lower() == "yes":
        print ("Begin entering IPs. Press ENTER after each line to add new line. Finish script with 'done' to proceed.\n")
        print ("Enter IPs\n")
        while massList != "done":
            massList = input('')
            if massList != "done":
                hostArray.append(massList)
        hostList = hostArray
        print ("Devices to process:\n")
        print (*hostList, sep = "\n") #has to be in a separate print statement
        #check pings on manual device list
        for host in hostList:
            try:
                pingThread.append(Thread(target=pingCheck, args=(host, pingResults)))
            except:
                print (f"{host} most likely not an IP. Skipping...")
            pingThread[-1].start()
    else:
        #check pings on devices loaded from ansible yml file
        print ("Continuing with host file...\n")        
        for host in hostList.items():
            try:
                pingThread.append(Thread(target=pingCheck, args=(host[1]['ansible_host'], pingResults)))
            except:
                exit()
            pingThread[-1].start()
    
    #Loads and decrypts credentials through RSA and Base64 from credential file.
    credInput['username'] = cred.localuser
    credInput['password'] = decrypt(cred.localpw, privateKey).decode()
    
    print ("\nEnter AD network authentication credentials as backup\n")
    credInput['username1'] = input('Username: ')
    credInput['password1'] = getpass()
    print ("Begin entering script. Press ENTER after each line to add new line. Finish script with 'copy run start' to proceed.\n")
    print ("\nEnter command:\n")
    while massScript != "copy run start":
        massScript = input('')    
        scriptArray.append(massScript)
    
    #wait for threads to finish before processing the results
    for pingT in pingThread:
        pingT.join()
    for key in pingResults:   #removes inactive hosts to prevent failure
        if not 'Request timed out' in pingResults[key] :
            activeHosts.append(key)
    
    if credInput['username1']:
        try:
            client.connect(coreIP, username=credInput['username1'], password=credInput['password1'], timeout=5) 
            transport = client.get_transport()
            transport.send_ignore()
        except ssh_exception.AuthenticationException:
            print ("AD Authentication Failed. Closing program")
            client.close()
            exit()
        
        
    
    for IPaddr in activeHosts:
        if IPaddr != "":
            print (f"{IPaddr} : spawning...")
            procTree = Process(target=sshProcess, args=(client, IPaddr, scriptArray, credInput))
            procs.append(procTree)
            procTree.start()
            time.sleep(.05)
        