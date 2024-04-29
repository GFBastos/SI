/***************************************************************************
*   Seguranca Informatica
*
*
***************************************************************************/
package mySNS;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

public class mySNSServer {

	public static void main(String[] args) {
		System.out.println("servidor: main");
		mySNSServer server = new mySNSServer();
		server.startServer();
	}

	public void startServer (){
		ServerSocket sSoc = null;
        
		try {
			System.setProperty("javax.net.ssl.keyStore", "keystore.server");
            System.setProperty("javax.net.ssl.keyStorePassword", "123456");
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			sSoc = ssf.createServerSocket(23456);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
         
		while(true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
		    }
		    catch (IOException e) {
		        e.printStackTrace();
		    }
		    
		}
		//sSoc.close();
	}


	//Threads utilizadas para comunicacao com os clientes
	class ServerThread extends Thread {

		private Socket socket = null;

		ServerThread(Socket inSoc) {
			socket = inSoc;
			System.out.println("thread do server para cada cliente");
		}
 
		public void run(){
			try {
				ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
				ObjectInputStream inStream = new ObjectInputStream(socket.getInputStream());
				
				File usersFile = new File("users.txt");
				if(!usersFile.exists()) {
					try {
					outStream.writeObject(false);
					System.out.println("SENT: false");
					
					String response = (String) inStream.readObject();
	    		    System.out.println("RECV: " + response);
	    		    
					usersPage users = usersPage.getInstance();
					
					String adminPassword = (String) inStream.readObject();
				    System.out.println("RECV: admin password");
				    
					outStream.writeObject("admin password received");
					System.out.println("SENT: admin password received");
					
					users.newUser("admin", adminPassword);
					}catch(IOException e) {
						System.err.println("Error communicating with server: " + e.getMessage());
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}else {
					outStream.writeObject(true);
					System.out.println("SENT: true");
					
					String response = (String) inStream.readObject();
	    		    System.out.println("RECV: " + response);
				}
				
				
				String actionFlag = (String) inStream.readObject();
			    System.out.println("RECV: action flag " + actionFlag);
			    
				outStream.writeObject("action flag received");
				System.out.println("SENT: action flag received");
			    
			    String action = null;
			    String utentUsername = null;
			    String utentPassword = null;
			    String medicUsername = null;
			    

			    // Handle the action based on the flag
			    switch (actionFlag) {
			    	case "-m":
			    		
			    		medicUsername = (String) inStream.readObject();
			    		System.out.println("RECV: medic username - " + medicUsername);
			        
			    		outStream.writeObject("medic username - " + medicUsername + " received");
			    		System.out.println("SENT: medic username - " + medicUsername + " received");
			    		break;
			    		
			    	case "-u":
			    		
			    		utentUsername = (String) inStream.readObject();
			    		System.out.println("RECV: utent username - " + utentUsername);
					
			    		outStream.writeObject("utent username - " + utentUsername + " received");
			    		System.out.println("SENT: utent username - " + utentUsername + " received");
					    break;
					    
			    	case "-au":
			    		try {
			    			
				    		//New user name
			    			utentUsername = (String) inStream.readObject();
				    		System.out.println("RECV: username - " + utentUsername);
						
				    		outStream.writeObject("username - " + utentUsername + " received");
				    		System.out.println("SENT: username - " + utentUsername + " received");
				    		
				    		
			    		}catch(IOException e) {
			    			System.err.println("Error communicating with server: " + e.getMessage());
			    		
					    break;
			    		}
			    }
			    utentPassword = (String) inStream.readObject();
			    System.out.println("RECV: utent password");
			    
				outStream.writeObject("utent password received");
				System.out.println("SENT: utent password received");
			    
				String actionFlag2 = null;
				if(!actionFlag.equals("-au")){
					actionFlag2 = (String) inStream.readObject();
				    System.out.println("RECV: action flag " + actionFlag2);
				    
					outStream.writeObject("action flag " + actionFlag2 + " received");
					System.out.println("SENT: action flag " + actionFlag2 + " received");
				}else {
					actionFlag2 = "-au";
				}
			    
			    // Handle the action based on the flag
				switch (actionFlag2) {
			    	case "-u":
			    		utentUsername = (String) inStream.readObject();
			    		System.out.println("RECV: utent username - " + utentUsername);
			    	  
			    		outStream.writeObject("utent username - " + utentUsername + " received");
			    		System.out.println("SENT: utent username - " + utentUsername + " received");
			    		break;
			    	case "-g":
			    		action = "-g";
//			    		action = (String) inStream.readObject();
//			    		System.out.println("RECV: action - " + action);
//			    		// Handle utent username here
//						outStream.writeObject("action " + action + " received");
//						System.out.println("SENT: action " + action + " received");
			    		break;
			    }
			    
			    if(actionFlag2.equals("-u")) {
			    	action = (String) inStream.readObject();
				    System.out.println("RECV: file action flag " + action);
				    
					outStream.writeObject("action " + action + " received");
					System.out.println("SENT: action " + action + " received");
			    }
			    else if(actionFlag2.equals("-au")) {
			    	action = "-au";
			    }
			    
				int numFiles = (int) inStream.readObject();
				System.out.println("RECV: Number of files");

				outStream.writeObject("File number received");
				System.out.println("SENT: File number received");
				
	    		//Authenticate user
				if(!actionFlag2.equals("-au")) {
					try {
						Boolean userAuthenticated = usersPage.getInstance().authenticate(utentUsername, utentPassword);
						
						outStream.writeObject(userAuthenticated);
						System.out.println("SENT: user authentication");
						
						String response = (String) inStream.readObject();
						System.out.println("RECV: " + response);
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				
				for (int i = 0; i < numFiles; i++) {
					byte[] buf = new byte[1024];
				    int bytesRead;
				    String fileName = (String) inStream.readObject();
				    System.out.println("RECV: File name");
					    
					outStream.writeObject("File name received");
					System.out.println("SENT: File name received");
					
					File encodedFile = new File("Utilizadores/" + utentUsername + "/" + fileName + ".cifrado");
		    		File certificate = new File("Utilizadores/" + utentUsername + "/" + fileName + ".assinatura." + medicUsername);
	    			File content = new File("Utilizadores/" + utentUsername + "/" + fileName + ".assinado");
	    			File safeFile = new File("Utilizadores/" + utentUsername + "/" + fileName + ".seguro");
	    			File keyFile = new File("Utilizadores/" + utentUsername + "/" + fileName + ".chave_secreta." + utentUsername);
	    			
					switch (action) {
				    	case "-sc":
				    		if(encodedFile.exists() || certificate.exists() || content.exists() || safeFile.exists() || keyFile.exists()) {
				    			outStream.writeObject(false);
				    		}else {
				    			outStream.writeObject(true);
				    			
					    		FileOutputStream kos = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".chave_secreta." + utentUsername);
					    		FileOutputStream fos1 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".cifrado");
					    		
					    		byte[] encryptedKeyBuffer = new byte[1024];
					    		int keyBytesRead = inStream.read(encryptedKeyBuffer); 
					    		kos.write(encryptedKeyBuffer, 0, keyBytesRead);
					    		kos.close();
					    		System.out.println("RECV: Encrypted key");
					    		
					    		outStream.writeObject("Key received");
					    		System.out.println("SENT: Key received");
					    		
					    		Long fileSize1 = (Long) inStream.readObject();
							    System.out.println("RECV: File size");
							      
								outStream.writeObject("File size received");
								System.out.println("SENT: File size received");
					    		
					    		long totalBytesRead1 = 0;  
					    		
							    while (totalBytesRead1 < fileSize1) {
							    	bytesRead = inStream.read(buf, 0, (int) Math.min(buf.length, fileSize1 - totalBytesRead1));
							    	if (bytesRead > 0) {
								        fos1.write(buf, 0, bytesRead);
								        fos1.flush();
								        totalBytesRead1 += bytesRead;
								    } else {
								        break; 
								    }
								}
							    System.out.println("RECV: Encrypted file");
							    
							    outStream.writeObject("File received");
							    System.out.println("SENT: File received");
							    
							    fos1.close();
							    break;
				    		}
				    		break;
				    	case "-sa":
				    		if(encodedFile.exists() || certificate.exists() || content.exists() || safeFile.exists() || keyFile.exists()) {
				    			outStream.writeObject(false);
				    		}else {
				    			outStream.writeObject(true);
				    			
								FileOutputStream fos2 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".assinatura." + medicUsername);
								FileOutputStream fos3 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".assinado");
							    
								long fileSize2 = (Long) inStream.readObject(); 
								long totalBytesRead2 = 0;
								System.out.println(fileSize2);
								System.out.println("RECV: File Size");
							    
							    outStream.writeObject("First File Size Received");
							    System.out.println("SENT: First File Size Received");
								
								long fileSize3 = (Long) inStream.readObject();
								System.out.println(fileSize3);
								System.out.println("RECV: File Size");
								    
							    outStream.writeObject("Second File Size Received");
							    System.out.println("SENT: Second File Size Received");
								
								while (totalBytesRead2 < fileSize2) {
								    bytesRead = inStream.read(buf, 0, (int) Math.min(buf.length, fileSize2 - totalBytesRead2));
								    if (bytesRead > 0) {
								        fos2.write(buf, 0, bytesRead);
								        fos2.flush();
								        totalBytesRead2 += bytesRead;
								    } else {
								        break; 
								    }
								}
							    
							    fos2.close();
							    
							    System.out.println("RECV: Signature");
							    
							    outStream.writeObject("Signature Received");
							    System.out.println("SENT: Signature Received");
							    
							   
								long totalBytesRead3 = 0;
							    
								while (totalBytesRead3 < fileSize3) {
									bytesRead = inStream.read(buf, 0, (int) Math.min(buf.length, fileSize3 - totalBytesRead3));
									if (bytesRead > 0) {
								        fos3.write(buf, 0, bytesRead);
								        fos3.flush();
								        totalBytesRead3 += bytesRead;
								    } else {
								        break; // End of stream reached unexpectedly
								    }
								}
	
							    fos3.close();
								
							    System.out.println("RECV: Signed File");
							    
							    outStream.writeObject("Signed File Received");
							    System.out.println("SENT: Signed File Received");
							    break;
				    		}
			    			break;
				    	case "-se":
				    		if(encodedFile.exists() || certificate.exists() || content.exists() || safeFile.exists() || keyFile.exists()) {
				    			outStream.writeObject(false);
				    		}else {
				    			outStream.writeObject(true);
				    			
					    		FileOutputStream fos4 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".assinatura." + medicUsername + ".seguro");
					    		FileOutputStream fos5 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".chave_secreta." + utentUsername + ".seguro");
					    		FileOutputStream fos6 = new FileOutputStream("Utilizadores/" + utentUsername + "/" + fileName + ".seguro");
					    		
					    		long fileSize4 = (Long) inStream.readObject(); 
								System.out.println("RECV: File Size");
	
								outStream.writeObject("File Size Received");
							    System.out.println("SENT: File Size Received");
								
								long fileSize6 = (Long) inStream.readObject(); 
								System.out.println("RECV: File Size");
								
								outStream.writeObject("File Size Received");
							    System.out.println("SENT: File Size Received");
					    		
								long totalBytesRead4 = 0;
					    		
							    while (totalBytesRead4 < fileSize4) {
							    	bytesRead = inStream.read(buf, 0, (int) Math.min(buf.length, fileSize4 - totalBytesRead4));
							    	if (bytesRead > 0) {
									    fos4.write(buf, 0, bytesRead);
									    fos4.flush();
									    totalBytesRead4 += bytesRead;
							    	} else {
							    		break;
							    	}
								}
							    fos4.close();
							    
							    System.out.println("RECV: Signature");
					    		
							    outStream.writeObject("Signature Received");
							    System.out.println("SENT: Signature Received");
							    
					    		
					    		byte[] encryptedKeyBuffer2 = new byte[1024];
					    		int keyBytesRead2 = inStream.read(encryptedKeyBuffer2); 
					    		fos5.write(encryptedKeyBuffer2, 0, keyBytesRead2);
					    		fos5.close();
					    		
					    		long totalBytesRead6 = 0;
							    while (totalBytesRead6 < fileSize6) {
							    	bytesRead = inStream.read(buf, 0, (int) Math.min(buf.length, fileSize6 - totalBytesRead6));
							    	if (bytesRead > 0) {
							    		fos6.write(buf, 0, bytesRead);
									    fos6.flush();
									    totalBytesRead6 += bytesRead;
							    	} else {
							    		break;
							    	}
								}
							    fos6.close();
							    
							    System.out.println("RECV: File");
							    
							    outStream.writeObject("File Received");
							    System.out.println("SENT: File Received");
				    		}
				    		break;
				    		
				    	case "-g":
				    		
			    			String request = null;

			    			if(encodedFile.exists() && keyFile.exists()) {
				    			outStream.writeObject("cifrado");
				    			request = "cifrado";
			    			}
				    		else if(certificate.exists() && content.exists()) {
				    			outStream.writeObject("assinado");
				    			request = "assinado";
				    		}
		    				else if(safeFile.exists() && keyFile.exists()) {
		    					outStream.writeObject("seguro");
		    					request = "seguro";
		    				}else {
		    					outStream.writeObject("");
		    				}
				    	
				    		
				    		switch(request) {
				    		
				    		case "cifrado":
				    			try {
					    			
					    			FileInputStream kfis = new FileInputStream(keyFile);
					    			byte[] encodedKeyBytes = new byte[(int) keyFile.length()]; 
					    			kfis.read(encodedKeyBytes);
					    			kfis.close();
					    			
									CifraHibrida.decrypt(utentUsername, "123456", fileName + ".cifrado", encodedKeyBytes);
									
									File fileToSend = new File("decrypted_" + fileName);
									FileInputStream fis2 = new FileInputStream(fileToSend);
									
					    			long fileSize5 = fileToSend.length();
				        			outStream.writeObject(fileSize5); 
				        			outStream.flush();
				        			System.out.println("SENT: File Size");
				        			String response = (String) inStream.readObject();
				        			
				        			System.out.println("RECV: " + response);
									
									byte[] buffer = new byte[1024];
									int bytesRead2;
									while ((bytesRead2 = fis2.read(buffer)) != -1) {
									    outStream.write(buffer, 0, bytesRead2);
									    outStream.flush();
									}
									fis2.close();
									System.out.println("SENT: decrypted file");
									
									String response1 = (String) inStream.readObject();
				        			
				        			System.out.println("RECV: " + response1);
									break;
								} catch (IOException e) {
									System.err.println("Error communicating with server: " + e.getMessage());
									break;
								} 
				    			
				    		case "assinado":
				    			try {
					    			Boolean result = Assinatura.verificar(content, certificate, utentUsername);
																		
									outStream.writeObject(result);
									System.out.println("SENT: result");
									
									break;
								}catch (FileNotFoundException e) {
									System.err.println("Error file not found: " + e.getMessage());
									break;
								}
				    			
				    		case "seguro":
				    			try {
					    			FileInputStream kfis = new FileInputStream(keyFile);
					    			byte[] encodedKeyBytes = new byte[(int) keyFile.length()]; 
					    			kfis.read(encodedKeyBytes);
					    			kfis.close();
									CifraHibrida.decrypt(utentUsername, "123456", encodedFile.getName(), encodedKeyBytes);
									
									File fileToSend = new File("decrypted_" + fileName);
					    			Boolean result = Assinatura.verificar( fileToSend , certificate, utentUsername);
																		
									outStream.writeObject(result);
									System.out.println("SENT: result");
									
									break;
								} catch (IndexOutOfBoundsException e) {
									System.err.println("Error incorrect file name provided: " + e.getMessage());
									break;
								} 
				    		}
				    		break;
				    		
				    	case "-au":
				    		try {
				    			
				    			Boolean found = usersPage.getInstance().checkName(utentUsername);
				    			
				    			outStream.writeObject(found);
				    			
					    		if(!found) {
						    		
						    		//New user folder
						    		File directory = new File("utilizadores/" +  utentUsername);
									directory.mkdir();
									System.out.println(String.format("New file for user %n created", utentUsername));
						
						    		
								    //Create new user
									usersPage.getInstance().newUser(utentUsername, utentPassword);
								    
					    		
						    		File cert = new File("Certificados/" + utentUsername + ".cert.crt");
						    		FileOutputStream cos = new FileOutputStream(cert);
						    		
						    		Long certificateSize = (Long) inStream.readObject();
								    System.out.println("RECV: Certificate size");
								      
									outStream.writeObject("Certificate size received");
									System.out.println("SENT: Certificate size received");
						    		
									byte[] buffer = new byte[1024];
								    int fstBytesRead;
									
						    		long totalBytesRead5 = 0;  
						    		
								    while (totalBytesRead5 < certificateSize) {
								    	fstBytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, certificateSize - totalBytesRead5));
								    	if (fstBytesRead > 0) {
									        cos.write(buffer, 0, fstBytesRead);
									        cos.flush();
									        totalBytesRead5 += fstBytesRead;
									    } else {
									        break; 
									    }
									}
								    cos.close();
					    		}else {
									System.err.println("User with same username already exists!");
								}
							    
							    
							    System.out.println("RECV: Certificate");
							    
							    outStream.writeObject("File received");
							    System.out.println("SENT: File received");
				    		
				    		} catch (NoSuchAlgorithmException e) {
				    			// TODO Auto-generated catch block
				    			e.printStackTrace();
				    		}
						}
				}
			 
				    
				System.out.println("thread: depois de receber ficheiros");
			}catch (ClassNotFoundException | IOException e1) {
				e1.printStackTrace();
			}

		}
	}
}