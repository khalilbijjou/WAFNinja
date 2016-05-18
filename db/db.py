"""

    :Program: WAFNinja
    :ModuleName: db
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The db module is responsible for the interaction with the database.

"""

import sqlite3
    
def getPayload(type, waf):
    """
        :Description: This function retrieves Payloads from the database.

        :param type:  Type of the Payload [sql | xss].
        :type type: String
        
        :param waf:  Payloads linked to a WAF
        :type waf: String
        
        :return: List of payloads
        
    """
    conn = sqlite3.connect("db/db.sqlite")
    c = conn.cursor()

    list = [type]
    sql = '''SELECT payload from payload where type=? '''
    
    if waf is not None:
        list.append(waf)
        sql = sql + 'and waf=? '

    c.execute(sql, (list))
    output = []
    for value in c.fetchall(): #the first item is the real payload
        output.append(value[0])
    try:         
        return output
    finally:
        conn.close()
     
def setPayload(input, type, waf):
    """
        :Description: This function adds a Payload to the database.

        :param input:  The Payload
        :type input: String
        
        :param type:  Type of the Payload [sql | xss].
        :type type: String
        
        :param waf:  The WAF the payload is going to be linked with
        :type waf: String
        
    """
    conn = sqlite3.connect("db/db.sqlite")
    c = conn.cursor()

    if waf is None:
        waf = 'generic'
    list = [input, type, waf]
    sql = '''Insert into payload (payload, type, waf) VALUES (?, ?, ?)'''
    c.execute(sql, (list))
    conn.commit()
    conn.close()
    print 'Payload inserted successfully!'
    
def getFuzz(type):
    """
        :Description: This function retrieves Fuzzing strings from the database.

        :param type:  Type of the Fuzzing string [sql | xss].
        :type type: String
               
        :return: List of Fuzzing strings
        
    """
    conn = sqlite3.connect("db/db.sqlite")
    c = conn.cursor()

    list = [type]
    sql = '''SELECT fuzz, expected from fuzz where type=?'''
    c.execute(sql, list)

    output = []
    for value in c.fetchall(): #the first item is the real payload
        output.append([value[0], value[1]])
    try:         
        return output
    finally:
        conn.close()    

def setFuzz(input, expected, type):
    """
        :Description: This function adds a Fuzzing string to the database.

        :param input:  The Fuzzing string
        :type input: String
        
        :param expected:  The expected output if the fuzzing string is included in a web server's response. Useful if the input is encoded in any way.
        :type expected: String
        
        :param type:  Type of the Fuzzing string [sql | xss].
        :type type: String
        
    """
    conn = sqlite3.connect("db/db.sqlite")
    c = conn.cursor()

    list = [input, expected, type]
    sql = '''Insert into fuzz (fuzz, expected, type) VALUES (?, ?, ?)'''
    c.execute(sql, (list))
    conn.commit()
    conn.close()
    print 'Fuzz inserted successfully!'
