dooh-security-scanner
---------------------
dooh security scanner, checks for exposure of admin panels, login panels, ports etc. and prints vulnerability report

Requirements
------------
1. Windows, Scanner runs on windows only
2. Ensure Java runtime is installed by searching for "get java" in google and install java version 11 and above
3. Download and copy nuclei.exe for windows from internet and copy it to target folder.

To Take Note
-------------
1. Ensure your antivirus software allow running Nuclei.exe.

Running the App
---------------
Extract the downloaded zip file to c:\dooh-security-scanner

There are 2 ways to run this app

Way 1 (For known ip addresses):

1.1 Open targets.txt and type in ip address one per line and save it
1.2 and double click  dooh-security-scanner-easy.bat

Way 2 (to discover ip address):

2.1 Double click dooh-security-scanner-discover-easy.bat
