"""

    :Program: WAFNinja
    :ModuleName: wafninja
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The wafninja module is the main module, that controls the flow of the program. 

"""

from argument import getArguments
from db.db import getPayload, setPayload, getFuzz, setFuzz
from db.setDB import testConnection, setDatabase
from ninja.bypass import firePayload
from ninja.fuzzer import fireFuzz

def setHeaders(cookie):
    """
        :Description: This function sets the cookie for the requests. 

        :param cookie:  A Cookie String
        :type cookie: String
        :todo: Add also other header
		
    """
    if cookie is not None:
        header.append(['Cookie',cookie])
        
def extractParams(input):
    """
        :Description: Takes the '-p' input and splits it into individual parameter

        :param input: POST Parameter
        :type input: String

        :return: Dictionary with the parameter as elements
        :note: This function is required to prepare the parameter for the firePayload() or fireFuzz() function
		
    """
    if input is None:
        return None
    input = input.split('&')
    params = {}
    for item in input:
        params[item.split('=',1)[0]] = item.split('=',1)[1]
    return params

arguments = getArguments()

if arguments[0] == 'bypass':
    arguments.pop(0) # delete the string that indicates what function to use
    url, post, cookie, type, delay, waf, outputFile = arguments
    payload = getPayload(type, waf)
    header = []
    setHeaders(cookie)
    post = extractParams(post)
    firePayload(type, payload, url, post, header, delay, outputFile)
        
elif arguments[0] == 'fuzz':
    arguments.pop(0)
    url, post, cookie, type, delay, outputFile = arguments
    fuzz = getFuzz(type)    
    header = []
    setHeaders(cookie)
    post = extractParams(post)
    fireFuzz(type, fuzz, url, post, header, delay, outputFile)
        
elif arguments[0] == 'insert-bypass':
    arguments.pop(0)
    input, type, waf = arguments
    setPayload(input, type, waf)
    
elif arguments[0] == 'insert-fuzz':
    arguments.pop(0)
    input, expected, type = arguments
    setFuzz(input, expected, type)

elif arguments[0] == 'set-db':
    arguments.pop(0)
    path = arguments[0]
    if (testConnection(path) == 1):
        setDatabase(path)
        print "Database sucessfully changed!"