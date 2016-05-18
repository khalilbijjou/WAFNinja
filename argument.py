"""

    :Program: WAFNinja
    :ModuleName: argument
    :Version: 1.0
    :Revision: 1.0.0
    :Author: Khalil Bijjou
    :Description: The argument module processes the command line arguments and provides it to the main module (wafninja module).

"""

import argparse
from argparse import RawTextHelpFormatter

def getArguments():
    """
        :Description: This function prints the start message and takes the arguments, which are passed by the user.

        :return: The user input
    """
    parser = argparse.ArgumentParser(description='''
    
___       ______________________   ______       ________        
__ |     / /__    |__  ____/__  | / /__(_)____________(_)_____ _
__ | /| / /__  /| |_  /_   __   |/ /__  /__  __ \____  /_  __ `/
__ |/ |/ / _  ___ |  __/   _  /|  / _  / _  / / /___  / / /_/ / 
____/|__/  /_/  |_/_/      /_/ |_/  /_/  /_/ /_/___  /  \__,_/  
                                                /___/           
                                                
    WAFNinja - Penetration testers favorite for WAF Bypassing
    
Example Usage:
fuzz:\n\tpython wafninja.py fuzz -u "http://www.target.com/index.php?id=FUZZ" \n\t-c "phpsessid=value" -t xss -o output.html 

bypass:\n\tpython wafninja.py bypass -u "http://www.target.com/index.php" \n\t-p "Name=PAYLOAD&Submit=Submit" \n\t-c "phpsessid=value" -t xss -o output.html

insert-fuzz:\n\tpython wafninja.py insert-fuzz -i select -e select -t sql
''',formatter_class=RawTextHelpFormatter, version='WAFNinja 1.0')
    subparser = parser.add_subparsers(help='Which function do you want to use?\n\n', dest='mode')
    attack_fuzz_parser = subparser.add_parser("fuzz",help='check which symbols and keywords are allowed by the WAF.')
    attack_payload_parser = subparser.add_parser("bypass",help='sends payloads from the database to the target.')
    insert_fuzz_parser = subparser.add_parser("insert-fuzz",help='add a fuzzing string')
    insert_bypass_parser = subparser.add_parser("insert-bypass",help='add a payload to the bypass list')
    set_db_parser = subparser.add_parser("set-db",help='use another database file. Useful to share the same database with others.')
    
    ## attack parser ##
    attack_payload_parser.add_argument('-u',metavar='URL',help='Target URL (e.g. "www.target.com/index.php?id=PAYLOAD")\nNote: specify the position of the payload with the keyword PAYLOAD',required=True)
    attack_payload_parser.add_argument('-p',metavar='POST PARAMETER',help='Send payload through post parameter ',required=False)    
    attack_payload_parser.add_argument('-c',metavar='COOKIE',help='HTTP Cookie Header',required=False)
    attack_payload_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'],help='Type of payload [sql|xss]', required=True)
    attack_payload_parser.add_argument('-d',metavar='DELAY',default='0',help="Wait the given delay time between each request [default=0]",required=False)
    attack_payload_parser.add_argument('-w',metavar='WAF',help='Send payloads of certain WAF [default=generic]', required=False)
    attack_payload_parser.add_argument('-o',metavar='OUTPUT FILE',help="Save output to .html file",required=False)
    
    ## attack fuzz ##
    attack_fuzz_parser.add_argument('-u',metavar='URL',help='Target URL (e.g. "www.target.com/index.php?id=FUZZ")\nNote: specify the position of the fuzz with the keyword FUZZ',required=True)
    attack_fuzz_parser.add_argument('-p',metavar='POST PARAMETER',help='Send fuzz through post parameter ',required=False)
    attack_fuzz_parser.add_argument('-c',metavar='COOKIE',help='HTTP Cookie Header',required=False)
    attack_fuzz_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'],help='Type of payload [sql|xss]', required=True)
    attack_fuzz_parser.add_argument('-d',metavar='DELAY',default=0,help="Wait the given delay time between each request [default=0]",required=False)
    attack_fuzz_parser.add_argument('-o',metavar='OUTPUT FILE',help="Save output to .html file",required=False)
    
    ## insert bypass parser ##
    insert_bypass_parser.add_argument('-i',metavar='INPUT',help='Payload to insert',required=True)
    insert_bypass_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'], help='Type of payload [sql|xss]',required=True)
    insert_bypass_parser.add_argument('-w',metavar='WAF',help='WAF that was bypassed with this payload', required=False)
    
    ## insert fuzz parser ##
    insert_fuzz_parser.add_argument('-i',metavar='INPUT',help='Fuzz to insert',required=True)
    insert_fuzz_parser.add_argument('-e',metavar='EXPECTED',help='Expected output from the target site. Use this option if input is encoded or something like that.',required=False)
    insert_fuzz_parser.add_argument('-t',metavar='TYPE',choices=['sql','xss'], help='Type of payload [sql|xss]',required=True)

    ## set database parser ##
    set_db_parser.add_argument('-p',metavar='PATH',help='Path to sqlite database. The default location is "db/db.sqlite"',required=True)
    
    args = parser.parse_args()


    if args.mode == 'bypass':
        url = args.u
        post = args.p
        cookie = args.c
        type = args.t.lower()
        delay = args.d
        waf = args.w
        if waf is not None:
            waf = waf.lower()
        outputFile = args.o
        return ['bypass', url, post, cookie, type, delay, waf, outputFile]
    
    elif args.mode == 'fuzz':
        url = args.u
        post = args.p
        cookie = args.c
        type = args.t.lower()
        delay = args.d
        outputFile = args.o
        return ['fuzz', url, post, cookie, type, delay, outputFile] 
    
    elif args.mode == 'insert-bypass':
        input = args.i
        type = args.t
        waf = args.w
        if waf is not None:
            waf = waf.lower()
        return ['insert-bypass', input, type, waf]
    
    elif args.mode == 'insert-fuzz':
        input = args.i
        if args.e is not None:
            expected = args.e
        else:
            expected = args.i
        type = args.t
        return ['insert-fuzz', input, expected, type]
        
    elif args.mode == 'set-db':
        path = args.p
        return ['set-db', path]
