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

import urllib
import urllib2
import copy
from time import sleep
from progressbar import *
from prettytable import PrettyTable

def firePayload(type, payloads, url, params, header, delay, outputFile):
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
    opener = urllib2.build_opener()
    for h in header:
        opener.addheaders.append(h)
    result = []
    
    for payload in pbar(payloads): # set the Payload
        try:
            sleep(float(delay))
            if params is None: # GET parameter           
                url_with_payload = insertPayload(url, payload)
                response = opener.open(url_with_payload)
            else: # POST parameter  
                params_with_payload = setParams(params, payload) 
                response = opener.open(url, urllib.urlencode(params_with_payload))
            content = response.read()
            occurence = content.find(payload)
            result.append({
                'payload' : payload,  
                'httpCode' : response.getcode(), 
                'contentLength': response.headers['content-length'], 
                'output' : content[occurence:occurence+len(payload)]})  # take string from occurence to occurence+len(expected)
        except urllib2.HTTPError, error: # HTTP Status != 200
            if error.code == 404:
                print 'ERROR: Target URL not reachable!'
                sys.exit()
            else: # HTTP Status != 404
                result.append({
                    'payload' : payload, 
                    'httpCode' : error.code, 
                    'contentLength': '-', 
                    'output' : '-'}) 
    showOutput(type, result, outputFile)  
            
def showOutput(type, result, outputFile):
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
        table = '<link rel="stylesheet" href="style.css">' + table
        table = table.replace('<td>Yes</td>', '<td class="Yes">Yes</td>')
        table = table.replace('<td>No</td>', '<td class="No">No</td>')
        table = table.replace('<td>Probably</td>', '<td class="Probably">Probably</td>')
        file = open(outputFile,'w')
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
    