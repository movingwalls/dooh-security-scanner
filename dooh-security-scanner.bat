java -cp dooh-security-scanner.jar com.dooh.DOOHSecurityScanner %1 %2
call scanner.bat
java -cp dooh-security-scanner.jar com.dooh.DOOHReportPrinter
cmd /k

