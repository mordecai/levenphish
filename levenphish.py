#!/usr/bin/python3
import sys
import os
import argparse
import whois
#usual copyright and disclaimer, pull the Levenshtein and whois python modules to make this work
#pip3 install python-Levenshtein
#pip3 install python-whois
parser = argparse.ArgumentParser(description="levenphish.py attempts to find possible phishes by comparing \
domain names within a mail header to actual third party vendor names. Levenphish will tell you if the \
provided domain name was found in a file that lists actual vendor domain names. The program will use \
the Levenshtein algorithm to detect if the domain name is similar to an existing vendor name and \
therefore a likely phish.  By default the program will alert if the two strings are fewer than two \
keystrokes apart; it will then kick off a WHOIS lookup on the likely rogue domain name.")

parser.add_argument("-v",metavar='',required=True,help= "A text file that lists vendor domain names")
parser.add_argument("-p",metavar='',required=True, help= "A possibly rogue domain name from a mail header")
parser.add_argument("-c",metavar='',action="store",type=int,default=2, \
help= "Optional override to the Levenshtein distance")

args = parser.parse_args()
inputname = args.p
if (args.c):
        lv = args.c
else: lv=2
findcount = 0

print ("\n ***************************\n")
from Levenshtein import distance
# Open the file with read only and get each line
try:
        f = open(args.v)
except FileNotFoundError:
        print("The file",args.v,"cannot be found\n")
        exit()
line = f.readlines()
for x in line:
        x =x.strip()
        edit_dist = distance(x, inputname)
#print("vendor name is ",x, "distance is" ,edit_dist)
#print("whois might blow up if rogue domain name is not present")
        if (edit_dist == 0):
                print ("Name provided",x, " is present in the list of vendors")
                findcount += 1
                exit
        elif (edit_dist <= lv):
                print ("possible phish found for vendor:",x, "- it is ",edit_dist,\
                "levenshtein away from ",inputname)
                try:
                        w=whois.whois(inputname)
                except PywhoisError:
                        print("the domain name",inputname,"cannot be found\n")
                        exit()
                print("\n    **** Whois information for ",inputname,"\n")
                print(inputname,"was created by ",w.name," on ",w.creation_date," in ", w.country,"\n")
                findcount += 1
if (findcount ==0):
         print (inputname,"was not found within the vendor name database ")
print ("\n ***************************\n")
