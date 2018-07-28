# levenphish
levenphish.py attempts to find possible phishes by comparing domain names within a mail header to actual third party vendor names. Levenphish will tell you if the provided domain name was found in a file that lists actual vendor domain names. The program will use the Levenshtein algorithm to detect if the domain name is similar to an existing vendor name and therefore a likely phish. By default the program will alert if the two strings are fewer than two keystrokes apart; it will then kick off a WHOIS lookup on the likely rogue
domain name.
