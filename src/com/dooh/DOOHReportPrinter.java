package com.dooh;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;

public class DOOHReportPrinter {
	public static void main(String[] args) {
		String currentDir = System.getProperty("user.dir");

		try
		{
			BufferedReader reader = new BufferedReader(new FileReader(currentDir + "\\config.txt"));
			String scanFolderName=reader.readLine();
			reader.close();

			File directory = new File(currentDir + "\\scans\\" + scanFolderName); // Replace with your directory

			// Fetch all files and directories
			File[] files = directory.listFiles();
			Arrays.sort(files, (f1, f2) -> f1.getName().compareTo(f2.getName()));
			int hostCount=0;
			int vulnCount=0;
			String vulnHost="";
			String prevValue="";
			String vulnComments="";
			
			System.out.println("-------------------------------------------------------------------------------------");
			System.out.println("DOOH PERIMETER DIAGNOSTIC AUDIT");
			System.out.println("-------------------------------------------------------------------------------------");
			
			
			for(int i=0;i<files.length;i++) {
				//System.out.println(files[i].getName());
				String line;

				String fileName=currentDir + "\\scans\\" +scanFolderName + "\\" + files[i].getName();

				BufferedReader reader1 = new BufferedReader(new FileReader(currentDir + "\\scans\\" +scanFolderName + "\\" + files[i].getName()));
				
				
				
				String fileParts[]=files[i].getName().split("--");
				if(!prevValue.equals(fileParts[0]) && !"".equals(prevValue))
				{
					hostCount++;
					
					if(!"".equals(prevValue))
					{
						if(!vulnHost.equals(prevValue)){
							System.out.println("[PASS]  " + prevValue + " -  No exposed DOOH management interfaces found");
						}else {
							System.out.println("[Fail]  " + prevValue + " -  " + vulnComments);
						}
					}
				}
				
				while ((line = reader1.readLine()) != null) {
					if(line.contains("matches found")) {
						//System.out.println(fileParts[0] + " is Vulnerable ");
						if(!vulnHost.equals(fileParts[0]))
						{
							vulnCount++;
							vulnHost=fileParts[0];
							vulnComments=fileParts[1].split("\\.")[0];
						}else {
							if("".equals(vulnComments))
								vulnComments=fileParts[1].split("\\.")[0];
							else
								vulnComments=vulnComments + "," + fileParts[1].split("\\.")[0];
						}
					}
					
				}
				reader1.close();
				prevValue=fileParts[0];
			}

			if(!"".equals(prevValue))
			{
				if(!vulnHost.equals(prevValue)){
					System.out.println("[PASS]  " + prevValue + " -  No exposed DOOH management interfaces found");
				}else {
					System.out.println("[Fail]  " + prevValue + " - " + vulnComments);
				}
			}
			
			
			hostCount++;
			System.out.println("------------------------------------------------------------------------------------------");
			System.out.println("Result " + vulnCount + "/" + hostCount + " vulnerable");
			System.out.println("Action: Close inbound WAN ports. Billboards should operate via outbound-only encrypted polling to CMS.");
		}catch(Exception ex) {
			ex.printStackTrace();
		}
	}
}
