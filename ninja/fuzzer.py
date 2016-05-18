"""
    Created on September 14, 2015
    
    :Program: WAFNinja
    :ModuleName: fuzzer
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The purpose of the fuzz function is to automate the reverse-engineering of the WAF's rule set by sending various fuzzing strings and see what is blocked and what not. 
                  In contrast to reverse-engineer the rule set manually, this function saves time, enhances the result by using a very broad amount of symbols and keywords and displays 
                  results in a clear and concise way. The result is either displayed in form of a table directly in the CLI or written to a HTML file if the '-o' argument is provided.

"""

import urllib
import urllib2
import copy
import string
import random
from time import sleep
from progressbar import *
from prettytable import PrettyTable

def fireFuzz(type, fuzz, url, params, header, delay, outputFile):
    """
        :Description: This function iterates through a list of fuzzing strings retrieved from the database, sends them to the target site and displays a progress bar of this process.

        :param type:  Type of the fuzzing strings to send [sql | xss].
        :type type: String
        
        :param fuzz:  Fuzzing strings
        :type fuzz: List
        
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
        
        :note: This function calls the showOutput() file with the saved outputs as argument.
        :todo: Add threads in order to send requests simultaneously.
		
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
    pbar = ProgressBar(widgets=[SimpleProgress(), ' Fuzz sent!    ', Percentage(), Bar()])
    opener = urllib2.build_opener()
    for h in header:
        opener.addheaders.append(h)
    result = []
    
    for fuzz in pbar(fuzz):
        expected = fuzz[1]
        fuzz = fuzz[0]
        
        try:
            sleep(float(delay))
            if params is None: # GET parameter
                randomString, url_with_fuzz = insertFuzz(url, fuzz) 
                response = opener.open(url_with_fuzz)
            else: # POST parameter
                randomString, params_with_fuzz = setParams(params, fuzz) 
                response = opener.open(url, urllib.urlencode(params_with_fuzz))
            content = response.read()
            occurence = content.find(randomString)+len(randomString) # get position of the randomString + length(randomString) to get to the fuzz
            result.append({
                'fuzz' : fuzz, 
                'expected' : expected, 
                'httpCode' : response.getcode(), 
                'contentLength': response.headers.get('Content-Length'),  
               'output' : content[occurence:occurence+len(expected)]}) # take string from occurence to occurence+len(expected)
        except urllib2.HTTPError, error: # HTTP Status != 200
            if error.code == 404:
                print 'ERROR: Target URL not reachable!'
                sys.exit()
            else: # HTTP Status != 404
                result.append({
                    'fuzz' : fuzz, 
                    'expected' : expected, 
                    'httpCode' : error.code, 
                    'contentLength': '-', 
                    'output' : '-'})
    showOutput(type, result, outputFile)  

        
            
def showOutput(type, result, outputFile):
    """
        :Description: This function prints the result of the fireFuzz() function in a nice fashion.

        :param type:  Type of the fuzzing strings that were sent
        :type type: String
        
        :param result: Contains the sent Fuzz, HTTP Code, Content-Length, expected string and the response's output
        :type result: List
        
        :param outputFile:  Name of Output file
        :type outputFile: String
        
        :note: This function saves the output in a HTML file or prints the output directly in the CLI.
    """
    
    table = PrettyTable(['Fuzz', 'HTTP Status', 'Content-Length', 'Expected', 'Output', 'Working'])
    for value in result:
        if (value['httpCode'] != 200):
            table.add_row([value['fuzz'], value['httpCode'], value['contentLength'], value['expected'], value['output'].strip(), 'No'])
        else:
            if(value['expected'] in value['output']): 
                table.add_row([value['fuzz'], value['httpCode'], value['contentLength'], value['expected'], value['output'], 'Yes'])
            else: 
                table.add_row([value['fuzz'], value['httpCode'], value['contentLength'], value['expected'], value['output'], 'Probably'])

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
    else:
        print table
        
def insertFuzz(url, fuzz):
    """
        :Description: This function inserts the Fuzz as GET Parameter in the URL 

        :param url: Target URL
        :type type: String
        
        :param fuzz: Fuzzing string
        :type fuzz: String

        :return: The URL with a concatenated string consisting of a random string and the fuzz.
        :note: Some fuzzing symbols can be part of a normal response. In order to distinctly find the fuzz that was sent, a random string is added before the fuzz.

    """

    fuzz = urllib.quote_plus(fuzz) #url encoding
    randomString = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return randomString, url.replace('FUZZ', randomString + str(fuzz))
    
def setParams(params, fuzz):
    """
        :Description: This function sets the Fuzz in the POST Parameter.

        :param url: Target URL
        :type type: String
        
        :param fuzz: Fuzzing string
        :type fuzz: String

        :return: The post parameter with a concatenated string consisting of a random string and the fuzz
        :note: Some fuzzing symbols can be part of a normal response. In order to distinctly find the fuzz that was sent, a random string is added before the fuzz.

    """
    
    randomString = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))
    parameter = copy.deepcopy(params) #makes a deep copy. this is needed because using a reference does not work
    for param in parameter:
        if parameter[param] == 'FUZZ':
            parameter[param] = randomString + str(fuzz)
    return randomString, parameter;
    