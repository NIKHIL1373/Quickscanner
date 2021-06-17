import requests
from termcolor import colored
from urllib.parse import urlparse


def scan(url,cookies):
    open_redirection_file_pointer=open('payloads/open_redirection.txt','r')
    for payload in open_redirection_file_pointer.readlines():
        payload = payload.strip('\n')
        try:
            op_url_parsed=urlparse(url)
            target=op_url_parsed.scheme+'://'+op_url_parsed.netloc+op_url_parsed.path+'?'
            #target=url+payload
            for query in op_url_parsed.query.split('&'):
                query_list=query.split('=')
                target+=query_list[0]+'='+payload+'&'
            target=target.rstrip('&')
            target+=op_url_parsed.fragment
            print(colored('\r[!] TRYING OPEN REDIRECTION VULNERABILITY FOR LINK '+target,'green'),flush=True,end='')
            try:
                res=requests.get(target,cookies=cookies)
                if(res.status_code!=404 and op_url_parsed.netloc not in res.url ):
                    for response in res.history:
                        if response.status_code == 301 or response.status_code == 302:
                              print(colored("\r[+] OPEN REDIRECTION VULNERABILITY EXISTS FOR THIS PAGE WITH PAYLOAD -->  "+target,'red',attrs=['bold']))
                              return
            except:
                pass
        except Exception as e:
            print(colored('[-] Exception --> '+str(e),'red'))
