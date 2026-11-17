package com.dooh;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class DOOHSecurityScanner {

	public static void main(String[] args) {
		try {
			String targets="";
			String target="";
 

			if(args[0].equals("-t"))
				targets=args[1];
			else if(args[0].equals("-h"))
				target=args[1];


			if(!"".equals(target) || !"".equals(targets)) {

				String[] linesArray=null;


				String currentDir = System.getProperty("user.dir");
				//System.out.println(currentDir);


				if(!"".equals(targets))
				{
					Path path=	Path.of(currentDir+"\\"+targets);
					List<String> linesList = Files.readAllLines(path);
					linesArray = linesList.toArray(new String[0]);

					// Remove Duplicates
					Set<String> uniqueLines = new LinkedHashSet<>(linesList);
					linesArray = uniqueLines.toArray(new String[0]);
			
					
				}
				else {
					linesArray=target.split(",");
				}

				UUID  uuid= UUID.randomUUID();
				java.io.File dir = new java.io.File(currentDir + "\\scans\\" + uuid.toString() + "\\");
				dir.mkdirs();

				BufferedWriter writer1 = new BufferedWriter(new FileWriter(currentDir+"\\config.txt"));
				writer1.write(uuid.toString());
				writer1.close();


				for(int j=0;j<linesArray.length;j++)
				{
					System.out.println(j);
					target=linesArray[j];

					File folder = new File(currentDir + "\\templates\\");

					// Get file/directory names as a String array
					String[] filesArray = folder.list();

					BufferedWriter writer = null;

					if (j==0)
						writer=new BufferedWriter(new FileWriter(currentDir+"\\scanner.bat"));
					else
						writer=new BufferedWriter(new FileWriter(currentDir+"\\scanner.bat",true));





					for(int i=0;i<filesArray.length;i++) {


						// java.io.File out = new java.io.File(dir, filesArray[i] + "." + target + ".txt");

						System.out.println("Writing commands : " + currentDir + "\\templates\\" + filesArray[i]);
						//ProcessBuilder pb = new ProcessBuilder("C:\\Users\\Shrini\\go\\bin\\nuclei.exe",
						//        "-u", target,"-t",currentDir + "\\templates\\" + filesArray[i],"-nc", "-silent");

						String prefixString="http://";

						if(filesArray[i].contains("http"))
							prefixString="http://";

						if(filesArray[i].contains("https"))
							prefixString="https://";


						writer.write("nuclei.exe -u "+ prefixString + target+ " -t \"" + currentDir + "\\templates\\" + filesArray[i] + "\" 2> \"" + currentDir + "\\scans\\" + uuid.toString() + "\\" + target + "--" + filesArray[i] + ".txt\"" +  "\r\n");

						//pb.redirectErrorStream(true);
						//pb.redirectOutput(ProcessBuilder.Redirect.appendTo(out));

						//Process p = pb.start();
						//int exit = p.waitFor();

					}

					writer.close();

				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
