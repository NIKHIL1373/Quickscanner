#!/usr/bin/pyton3
from termcolor import colored
from  urllib.parse import urlparse
import requests
import threading

count=0
vulnerable_pages_list=[]

size=170
#design function 
def f():
	#print('       ',end='')
	print(colored('-'*size,'white','on_grey',['dark']))


def test(url,line,file_pointer_default,headers):
	global count , vulnerable_pages_list
	try:
		print(colored('[!] TRYING FOR VULNEARBLE PAGE --> '+url+'/'+line,'white',attrs=['dark']),flush=False,end='\n')
		#time.sleep(0.1)
		res=requests.get(url+'/'+line,headers=headers)
		if(res.status_code==200):
			print(colored('[+] FOUND VULNEARBLE PAGE (DEFAULT PAGE) --> '+url+'/'+line,'red',attrs=['bold']))
			count+=1
			file_pointer_default.write(url+'/'+line+'\n')
			vulnerable_pages_list.append(url+'/'+line)
	except Exception as e:
		print(colored("[!] PAGE NOT FOUND -->"+url+'/'+line,'red'),flush=False,end='\n')
		print(e)
	
#/usr/share/wordlists/dirb/vulns
def vulnerable_pages(url,headers):
	try:
		urlparsed=urlparse(url)
		url=urlparsed.scheme+'://'+urlparsed.netloc
		file_pointer=open('payloads/vulnerable_default_pages.txt')
		file_pointer_default=open('report/default_vulnerable_pages.txt','w')
		reading_file=file_pointer.readlines()
		for line in reading_file:
			line=line.strip('\n')
			t=threading.Thread(target=test,args=(url,line,file_pointer_default,headers))
			t.start()
			
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING DEFAULT VULNEARBLE PAGE CHECKING ','red',attrs=['bold']))
	except Exception as e:
		print((colored('[-]'+str(e),'red')))