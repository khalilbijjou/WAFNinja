"""
    Created on September 14, 2015
    
    :Program: WAFNinja
    :ModuleName: bypass
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The bypass function automates the brute forcing of the WAF by enumerating payloads. These are taken from the database and embedded in requests and then sent to the web 
                  server. The response of every request is analyzed individually. The result is either displayed in form of a table directly in the CLI or written to a HTML file if 
                  the '-o' argument is provided.
                  
"""

import copy
from prettytable import PrettyTable
from progressbar import *
import ssl
import codecs
from time import sleep
import urllib
import urllib2

def firePayload(type, payloads, url, params, header, delay, outputFile, proxy, prefix, postfix):
    """
        :Description: This function iterates through a list of payloads retrieved from the database, sends them to the target site and displays a progress bar of this process.

        :param type:  Type of the payload [sql | xss].
        :type type: String
        
        :param payloads:  Payload strings
        :type payloads: List
        
        :param url: Target URL
        :type url: String
        
        :param params: POST Parameter
        :type params: String
        
        :param header: Cookie header
        :type header: String
        
        :param delay: Delay between requests
        :type delay: Float
        
        :param outputFile:  Name of Output file
        :type outputFile: String
        
        :note: This function calls the showOutput() file with the saved outputs as argument
        :todo: Add threads in order to send requests simultaneously
		
    """
    print '''
___       ______________________   ______       ________        
__ |     / /__    |__  ____/__  | / /__(_)____________(_)_____ _
__ | /| / /__  /| |_  /_   __   |/ /__  /__  __ \____  /_  __ `/
__ |/ |/ / _  ___ |  __/   _  /|  / _  / _  / / /___  / / /_/ / 
____/|__/  /_/  |_/_/      /_/ |_/  /_/  /_/ /_/___  /  \__,_/  
                                                /___/           

WAFNinja - Penetration testers favorite for WAF Bypassing
    '''
    pbar = ProgressBar(widgets=[SimpleProgress(), ' Payloads sent!    ', Percentage(), Bar()])
    if proxy is not '':
        httpProxy = urllib2.ProxyHandler({'http': proxy, 'https': proxy})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx), httpProxy)
        urllib2.install_opener(opener)
    else:
        opener = urllib2.build_opener()
    opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
    for h in header:
        opener.addheaders.append(h)
    result = []   
    
    for payload in pbar(payloads): # set the Payload
        payload = prefix + payload + postfix
        payload_enc = payload.encode('utf-8')
        try:
            sleep(float(delay))
            if params is None: # GET parameter           
                url_with_payload = insertPayload(url, payload_enc)
                response = opener.open(url_with_payload)
            else: # POST parameter  
                params_with_payload = setParams(params, payload_enc) 
                response = opener.open(url, urllib.urlencode(params_with_payload))
            content = response.read()
            occurence = content.find(payload_enc)
            result.append({
                          'payload': payload_enc, 
                          'httpCode': response.getcode(), 
                          'contentLength': len(content),
                          'output': content[occurence:occurence + len(payload_enc)]})  # take string from occurence to occurence+len(expected)
        except urllib2.HTTPError, error: # HTTP Status != 200
            if error.code == 404:
                print 'ERROR: Target URL not reachable!'
                sys.exit()
            else: # HTTP Status != 404
                result.append({
                              'payload': payload_enc, 
                              'httpCode': error.code, 
                              'contentLength': '-', 
                              'output': '-'}) 
    showOutput(type, url, result, outputFile, delay, proxy, prefix, postfix)  
            
def showOutput(type, url, result, outputFile, delay, proxy, prefix, postfix):
    """
        :Description: This function prints the result of the firePayload() function in a nice fashion 

        :param type:  Type of the payload strings that were sent
        :type type: String
        
        :param result: List which contains the sent Payload, HTTP Code, Content-Length and the response's output
        :type result: List
        
        :param outputFile:  Name of Output file
        :type outputFile: String
        
        :note: Saves the output in a HTML file or prints the output directly in the CLI.
    """
    if type == 'xss':
        table = PrettyTable(['Payload', 'HTTP Status', 'Content-Length', 'Output', 'Working'])
        for value in result:
            if (value['httpCode'] != 200):
                table.add_row([value['payload'], value['httpCode'], value['contentLength'], value['output'], 'No'])
            else:
                if (value['payload'] == value['output']):
                    table.add_row([value['payload'], value['httpCode'], value['contentLength'], value['output'], 'Yes'])
                else:
                    # Expected not in Output found, could have been filtered
                    table.add_row([value['payload'], value['httpCode'], value['contentLength'], value['output'], 'Probably'])
    elif type == 'sql':
        table = PrettyTable(['Payload', 'HTTP Status', 'Content-Length', 'Working'])
        for value in result:
            if (value['httpCode'] != 200):
                table.add_row([value['payload'], value['httpCode'], value['contentLength'], 'No'])            
            else:
                table.add_row([value['payload'], value['httpCode'], value['contentLength'], 'Yes'])

    if outputFile is not None:
        table = table.get_html_string(attributes={"class":"OutputTable"})
        table = '<h1>WAFNinja - Penetration testers favorite for WAF Bypassing</h1>' + '<b>URL</b>: ' + url + '<br>' + '<b>TYPE: </b>' + type + '<br>' + '<b>DELAY: </b>' + delay + '<br>' + '<b>PROXY: </b>' + proxy + '<br>' + '<b>PREFIX: </b>' + prefix + '<br>' + '<b>POSTFIX: </b>' + postfix + '<br><br>' + table
        table = '''<meta charset="utf-8"/><style>
        .OutputTable {
	margin:0px;padding:0px;
	width:100%;
	border:1px solid #000000;
	
	-moz-border-radius-bottomleft:10px;
	-webkit-border-bottom-left-radius:10px;
	border-bottom-left-radius:10px;
	
	-moz-border-radius-bottomright:10px;
	-webkit-border-bottom-right-radius:10px;
	border-bottom-right-radius:10px;
	
	-moz-border-radius-topright:10px;
	-webkit-border-top-right-radius:10px;
	border-top-right-radius:10px;
	
	-moz-border-radius-topleft:10px;
	-webkit-border-top-left-radius:10px;
	border-top-left-radius:10px;
	table-layout: fixed;
        }.OutputTable table{
            border-collapse: collapse;
                border-spacing: 0;
                width:310px;
                height:100%;
                margin:0px;padding:0px;
        }.OutputTable tr:last-child td:last-child {
                -moz-border-radius-bottomright:10px;
                -webkit-border-bottom-right-radius:10px;
                border-bottom-right-radius:10px;
        }
        .OutputTable table tr:first-child td:first-child {
                -moz-border-radius-topleft:10px;
                -webkit-border-top-left-radius:10px;
                border-top-left-radius:10px;
        }
        .OutputTable table tr:first-child td:last-child {
                -moz-border-radius-topright:10px;
                -webkit-border-top-right-radius:10px;
                border-top-right-radius:10px;
        }.OutputTable tr:last-child td:first-child{
                -moz-border-radius-bottomleft:10px;
                -webkit-border-bottom-left-radius:10px;
                border-bottom-left-radius:10px;
        }.OutputTable tr:hover td{
                background-color:#ffffff;
        }
        .OutputTable td{
                vertical-align:middle;
                background-color:#ffffff;
                width:500px; 
                word-wrap: break-word;
            height: 15px;
                border:1px solid #000000;
                border-width:0px 1px 1px 0px;
                text-align:center;
                padding:9px;
                font-size:15px;
                font-family:Helvetica;
                font-weight:normal;
                color:#000000;
        }.OutputTable tr:last-child td{
                border-width:0px 1px 0px 0px;
        }.OutputTable tr td:last-child{
                border-width:0px 0px 1px 0px;
        }.OutputTable tr:last-child td:last-child{
                border-width:0px 0px 0px 0px;
        }
        .OutputTable tr:first-child th{
                        background:-o-linear-gradient(bottom, #007fff 5%, #007fff 100%);	background:-webkit-gradient( linear, left top, left bottom, color-stop(0.05, #007fff), color-stop(1, #007fff) );
                background:-moz-linear-gradient( center top, #007fff 5%, #007fff 100% );
                filter:progid:DXImageTransform.Microsoft.gradient(startColorstr="#007fff", endColorstr="#007fff");	background: -o-linear-gradient(top,#007fff,007fff);

                background-color:#007fff;
                border:0px solid #000000;
                text-align:center;
                border-width:0px 0px 1px 1px;
                font-size:15px;
                font-family:Courier;
                font-weight:bold;
                color:#ffffff;
        }
        .OutputTable tr:first-child:hover td{
                background:-o-linear-gradient(bottom, #007fff 5%, #007fff 100%);	background:-webkit-gradient( linear, left top, left bottom, color-stop(0.05, #007fff), color-stop(1, #007fff) );
                background:-moz-linear-gradient( center top, #007fff 5%, #007fff 100% );
                filter:progid:DXImageTransform.Microsoft.gradient(startColorstr="#007fff", endColorstr="#007fff");	background: -o-linear-gradient(top,#007fff,007fff);

                background-color:#007fff;
        }
        .OutputTable tr:first-child td:first-child{
                border-width:0px 0px 1px 0px;
        }
        .OutputTable tr:first-child td:last-child{
                border-width:0px 0px 1px 1px;
        }
        .OutputTable td.Yes{
                background-color:#00FF00;
        }
        .OutputTable td.No{
                background-color:#FF0000;
        }
        .OutputTable td.Probably{
                background-color:#00CCFF;
        }
            </style>''' + table
        table = table.replace('<td>Yes</td>', '<td class="Yes">Yes</td>')
        table = table.replace('<td>No</td>', '<td class="No">No</td>')
        table = table.replace('<td>Probably</td>', '<td class="Probably">Probably</td>')
        file = codecs.open(outputFile, 'w', encoding='utf-8')
        file.write(table) 
        file.close() 
        print 'Output saved to ' + outputFile + '!'
        print 'Good luck.'
    else:
        print table

def insertPayload(url, payload):
    """
        :Description: This function inserts the Payload as GET Parameter in the URL 

        :param url: Target URL
        :type type: String
        
        :param payload: Payload string
        :type payload: String

        :return: The URL with a concatenated string consisting of a random string and the payload.
        :note: In order to distinctly find the payload that was sent, a random string is added before the payload.
        
    """
    payload = payload.replace(' ', '+') #replace whitespaces with a '+'
    return url.replace('PAYLOAD', payload)
    
def setParams(params, payload):
    """
        :Description: This function sets the Payload in the POST Parameter.

        :param url: Target URL
        :type type: String
        
        :param payload: Payload string
        :type payload: String

        :return: The post parameter with a concatenated string consisting of a random string and the payload.
        :note: In order to distinctly find the payload that was sent, a random string is added before the payload.

    """
    parameter = copy.deepcopy(params) #makes a deep copy, otherwise reference and wont work
    for param in parameter:
        if parameter[param] == 'PAYLOAD':
            parameter[param] = payload
    return parameter;
    