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
			sSoc = new ServerSocket(23456);
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
				    		String newUsername = (String) inStream.readObject();
				    		System.out.println("RECV: username - " + newUsername);
						
				    		outStream.writeObject("username - " + newUsername + " received");
				    		System.out.println("SENT: username - " + newUsername + " received");
				    		
				    		Boolean found = usersPage.getInstance().checkName(newUsername);
				    		
				    		if(!found) {
					    		//New user password
					    		String newUserPass = (String) inStream.readObject();
					    		System.out.println("RECV: password");
							
					    		outStream.writeObject("password received");
					    		System.out.println("SENT: password received");
					    		
					    		//New user folder
					    		File directory = new File("utilizadores/" +  newUsername);
								directory.mkdir();
								System.out.println(String.format("New file for user %n created", newUsername));
								
								//New user certificate
								File cert = new File("utilizadores/" +  newUsername + "/" + newUsername + ".certificate");
					    		FileOutputStream cos = new FileOutputStream(cert);
					    		
					    		Long certificateSize = (Long) inStream.readObject();
							    System.out.println("RECV: Certificate size");
							      
								outStream.writeObject("Certificate size received");
								System.out.println("SENT: Certificate size received");
					    		
								byte[] buffer = new byte[1024];
							    int fstBytesRead;
								
					    		long totalBytesRead1 = 0;  
					    		
							    while (totalBytesRead1 < certificateSize) {
							    	fstBytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, certificateSize - totalBytesRead1));
							    	if (fstBytesRead > 0) {
								        cos.write(buffer, 0, fstBytesRead);
								        cos.flush();
								        totalBytesRead1 += fstBytesRead;
								    } else {
								        break; 
								    }
								}
							    
							    cos.close();
							    
							    System.out.println("RECV: Encrypted file");
							    
							    outStream.writeObject("File received");
							    System.out.println("SENT: File received");
					    		
							    //Create new user
								usersPage.getInstance().newUser(newUsername, newUserPass);
							    
				    		}else {
								System.err.println("User with same username already exists!");
							}
			    		}catch(IOException e) {
			    			System.err.println("Error communicating with server: " + e.getMessage());
			    		} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					    break;
		    	}
			    
			    utentPassword = (String) inStream.readObject();
			    System.out.println("RECV: utent password");
			    
				outStream.writeObject("utent password received");
				System.out.println("SENT: utent password received");
			    
			    String actionFlag2 = (String) inStream.readObject();
			    System.out.println("RECV: action flag " + actionFlag2);
			    
				outStream.writeObject("action flag " + actionFlag2 + " received");
				System.out.println("SENT: action flag " + actionFlag2 + " received");
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
			    
				int numFiles = (int) inStream.readObject();
				System.out.println("RECV: Number of files");

				outStream.writeObject("File number received");
				System.out.println("SENT: File number received");
				
	    		//Authenticate user
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
				
				for (int i = 0; i < numFiles; i++) {
					byte[] buf = new byte[1024];
				    int bytesRead;
					
				    String fileName = (String) inStream.readObject();
				    System.out.println("RECV: File name");
					    
					outStream.writeObject("File name received");
					System.out.println("SENT: File name received");
					switch (action) {
				    	case "-sc":
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
				    	case "-sa":
							
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
				    	case "-se":
				    		
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
						    
				    		break;
				    		
				    	case "-g":
				    		String[] fileState = fileName.split("\\.");
				    		switch(fileState[fileState.length - 1]) {
				    		
				    		case "cifrado":
				    			
				    			try {
				    				String requestedFileName = fileState[0] + "." + fileState[1];
					    			File keyFile = new File("Utilizadores/" + utentUsername + "/" + requestedFileName + ".chave_secreta." + utentUsername);
					    			FileInputStream kfis = new FileInputStream(keyFile);
					    			byte[] encodedKeyBytes = new byte[(int) keyFile.length()]; 
					    			kfis.read(encodedKeyBytes);
					    			kfis.close();
					    			
									CifraHibrida.decrypt(utentUsername, "123456", fileName, encodedKeyBytes);
									
									File fileToSend = new File("decrypted_" + requestedFileName);
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
				    				//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				    				//TODO
					    			File certificate = new File("Utilizadores/" + utentUsername + "/a.txt.assinatura.silva");
					    			File content = new File("Utilizadores/" + utentUsername + "/a.txt.assinado");
					    			//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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
				    				medicUsername = fileState[fileState.length - 2];
				    				String file = fileName.replace(".assinatura." + medicUsername,"");
									String requestedFileName = fileState[0] + "." + fileState[1];
									File keyFile = new File("Utilizadores/" + utentUsername + "/" + requestedFileName + ".chave_secreta." + utentUsername + ".seguro");
					    			FileInputStream kfis = new FileInputStream(keyFile);
					    			byte[] encodedKeyBytes = new byte[(int) keyFile.length()]; 
					    			kfis.read(encodedKeyBytes);
					    			kfis.close();
									CifraHibrida.decrypt(utentUsername, "123456", file, encodedKeyBytes);
									
									File fileToSend = new File("decrypted_" + requestedFileName);
									File certificate = new File("Utilizadores/" + utentUsername + "/" + requestedFileName + ".assinatura." + medicUsername + ".seguro");
					    			Boolean result = Assinatura.verificar( fileToSend , certificate, utentUsername);
																		
									outStream.writeObject(result);
									System.out.println("SENT: result");
									
									break;
								} catch (IndexOutOfBoundsException e) {
									System.err.println("Error incorrect fil name provided: " + e.getMessage());
									break;
								} 
				    		}
				    		break;
				    }
				    	
			    }
				    
				System.out.println("thread: depois de receber ficheiros");
			}catch (ClassNotFoundException | IOException e1) {
				e1.printStackTrace();
			}

		}
	}
}