"""

    :Program: WAFNinja
    :ModuleName: setDB
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The set-db function is used to change the database used by WAFNinja. This is especially useful, if the tool is used in a team environment. Penetration tester
                  can share the same database. Thereby a payload, that was inserted by a team member, will be available for the whole team.

"""

import sqlite3
import re

def testConnection(path):
    """
        :Description: This function tests wether the provided path is correct and the file is a WAFNinja database.

        :param path:  Path to database.
        :type path: String
        
        :return: True or False
        
    """
    conn = sqlite3.connect(path)
    try:
        conn.execute("Select payload from payload")
        return True
    except:
        print "Could not open database!"
        return False

def setDatabase(path):
    """
        :Description: This function replaces the database path in the db module.

        :param path:  Path to database.
        :type path: String
        
        :to-do: Use a config file for the path to the database. Changing program code directly is not the best method.
    """
    with open('db/db.py','r') as f:
        newlines = []
        for line in f.readlines():
            newlines.append(re.sub(r"(.:)?(\w+)?(\\\w+|\/\w+)+.sqlite", path, line))
    with open('db/db.py', 'w') as f:
        for line in newlines:
            f.write(line)