package mySNS;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.io.FileNotFoundException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;


public class mySNSClient {

    public static void main(String[] args) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, ClassNotFoundException {
        Socket socket = null;
		String serverAdress =args[1];
		int serverPort = 23456;
		boolean verified = false;
		boolean existsUsersFile = false;
		
		try {
			System.setProperty("javax.net.ssl.trustStore", "truststore.client");
            System.setProperty("javax.net.ssl.trustStorePassword", "123456");
			SocketFactory sf = SSLSocketFactory.getDefault();
			socket = sf.createSocket(serverAdress, serverPort);
		} catch (UnknownHostException e) {
			System.err.println("Error unknown host: " + e.getMessage());
		} catch (IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		}
        
        ObjectOutputStream out = null;
		try {
			out = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		}
        ObjectInputStream in = null;
		try {
			in = new ObjectInputStream(socket.getInputStream());
		} catch (IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		}
		try {
			/*Scanner scanner = new Scanner(System.in);
			System.out.print("Enter new admin password: ");
			String password = scanner.nextLine();
			
			out.writeObject(password);
		    System.out.println("SENT: password");

		    String response = (String) in.readObject();
		    System.out.println("RECV: " + response);
			*/
			existsUsersFile = (Boolean) in.readObject();
			System.out.println("RECV: Exists user file: " + existsUsersFile);
			
			out.writeObject("received about users file");
		    System.out.println("SENT: received about users file");
			
		    if(existsUsersFile) {
				verified = (boolean)in.readObject();
				
				System.out.println("RECV: verification " + verified);
				
				out.writeObject("Verification received");
				System.out.println("SENT: Verification received");
			}
		}catch(IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
        
        String medicUsername = null;
        String utentUsername = null;
        String[] fileNames = null;
        String action = null;
        String password = null;
        
        //MAC VERIFICATION
        if(!verified && existsUsersFile) {
        	System.err.println("Error authenticating user");
        	try {
        		out.close();
        		socket.close();
        	}catch(IOException e) {
        		System.err.println("Error communicating with server: " + e.getMessage());
        	}
        }
        
        switch (args[2]){
        	case "-m":
        		  try {
        			  action = args[8];
        			  medicUsername = args[3];
        			  out.writeObject("-m");
        			  System.out.println("SENT: -m");

        			  String response1 = (String) in.readObject();
        			  System.out.println("RECV: " + response1);

        			  out.writeObject(medicUsername);
        			  System.out.println("SENT: medic username");

        			  String response2 = (String) in.readObject();
        			  System.out.println("RECV: " + response2);
        		  } catch (IOException e) {
        			  System.err.println("Error communicating with server: " + e.getMessage());
        		  } catch (ClassNotFoundException e) {
        			  System.err.println("Error reading response: " + e.getMessage());
        		  }
        		  break;

        	case "-u":
        		try {
        			utentUsername = args[3];
	    		    out.writeObject("-u");
	    		    System.out.println("SENT: -u");
	
	    		    String response3 = (String) in.readObject();
	    		    System.out.println("RECV: " + response3);
	
	    		    out.writeObject(utentUsername);
	    		    System.out.println("SENT: utent username");
	
	    		    String response4 = (String) in.readObject();
	    		    System.out.println("RECV: " + response4);
        		} catch (IOException e) {
        		    System.err.println("Error communicating with server: " + e.getMessage());
        		} catch (ClassNotFoundException e) {
        			System.err.println("Error reading response: " + e.getMessage());
        		}
        		  break;
        	case "-au":
        		try {
        			String newUsername = args[3];
        			String newUserPass = args[5];
        			
        			action = "-au";
        			out.writeObject(action);
        			System.out.println("SENT: action flag -au");
        			
        			String response4 = (String) in.readObject();
        		    System.out.println("RECV: " + response4);
        		    
        		    boolean verification = (boolean) in.readObject();
        		    System.out.println("RECV: verification " + verification);
        		    
        		    out.writeObject("received verification " + verification);
        		    System.out.println("SENT: received verification " + verification);
        		    
        		    //MAC VERIFICATION
        	        if(!verification) {
        	        	System.err.println("Error authenticating user");
        	        	try {
        	        		out.close();
        	        		socket.close();
        	        	}catch(IOException e) {
        	        		System.err.println("Error communicating with server: " + e.getMessage());
        	        	}
        	        }
        		    
        		    //Send the username
        		    out.writeObject(newUsername);
        			System.out.println("SENT: username " + newUsername);
        			
        			String response5 = (String) in.readObject();
        		    System.out.println("RECV: " + response5);
        		    
        		    
        		}catch(IOException e) {
        			System.err.println("Error communicating with server: " + e.getMessage());
        		} catch (ClassNotFoundException e) {
        			System.err.println("Error reading response: " + e.getMessage());
				}
        }
        if(args[4].equals("-p")) {
        	try {
        		password = args[5];
				out.writeObject(password);
    			System.out.println("SENT: password");
    			
    			String response6 = (String) in.readObject();
    		    System.out.println("RECV: " + response6);
        	}catch(IOException e) {
        		System.err.println("Error communicating with server: " + e.getMessage());
        	}
				
        }else {
        	System.err.println("Password was not provided");
        }
        switch (args[6]){
        	case "-u":
        		try {
	        	    utentUsername = args[7]; 
	        	    out.writeObject("-u");
	        	    System.out.println("SENT: -u");
	
	        	    String response1 = (String) in.readObject();
	        	    System.out.println("RECV: " + response1);
	
	        	    out.writeObject(utentUsername);
	        	    System.out.println("SENT: utent username");
	
	        	    String response2 = (String) in.readObject();
	        	    System.out.println("RECV: " + response2);
        	  } catch (IOException e) {
        		  System.err.println("Error communicating with server: " + e.getMessage());
        	  } catch (ClassNotFoundException e) {
        		  System.err.println("Error reading response: " + e.getMessage());
        	  }
        		break;

        	case "-g":
        		try {
        		    action = "-g";
        		    out.writeObject(action);
        		    System.out.println("SENT: -g");

        		    String response3 = (String) in.readObject();
        		    System.out.println("RECV: " + response3);

//        		    out.writeObject(action); // Sending action again (assuming intended behavior)
//        		    System.out.println("SENT: action"); // Sending action again (assuming intended behavior)

//        		    String response4 = (String) in.readObject();
//        		    System.out.println("RECV: " + response4);

        		    fileNames = Arrays.copyOfRange(args, 7, args.length);
        		} catch (IOException e) {
        		    System.err.println("Error communicating with server: " + e.getMessage());
        		} catch (ClassNotFoundException e) {
        			System.err.println("Error reading response: " + e.getMessage());
        		}
        		break;
        	}
        if (!action.equals("-g") && !action.equals("-au")) {
        	try {
        		  action = args[8]; 
        		  out.writeObject(action);
        		  System.out.println("SENT: action");

        		  String response1 = (String) in.readObject();
        		  System.out.println("RECV: " + response1);

        		  fileNames = Arrays.copyOfRange(args, 9, args.length);
    		} catch (IOException e) {
    		  System.err.println("Error communicating with server: " + e.getMessage());
    		} catch (ClassNotFoundException e) {
    		  System.err.println("Error reading response: " + e.getMessage());
    		}
        		
        }
        
        if(action.equals("-au")) {
        	fileNames = Arrays.copyOfRange(args, 6, args.length);
        }
        
        
        ArrayList<File> fileList = new ArrayList<File>();

        for (String fileName : fileNames) {
        	File file = new File(fileName);
           
            if (!file.exists() && !action.equals("-g")) {
                System.err.println("Error: File " + fileName + " not found!");
            }else if(file.exists() && action.equals("-g")){
            	System.err.println("Error: File " + fileName + " already exists in the client side!");
            }else {
            	fileList.add(file);
            }
        }
        
        
        try {
        	  out.writeObject(fileList.size());
        	  out.flush();
        	  System.out.println("SENT: " + fileList.size() + " as number of files");

        	  String response1 = (String) in.readObject();
        	  System.out.println("RECV: " + response1);
    	} catch (IOException e) {
    		System.err.println("Error communicating with server: " + e.getMessage());
    	} catch (ClassNotFoundException e) {
    		System.err.println("Class not found: " + e.getMessage());
		}
        
        //User authentication
        if(!action.equals("-au")) {
	        try {
	        Boolean userAuthenticated = (Boolean) in.readObject();
	        System.out.println("RECV: " + userAuthenticated);
	        
	        out.writeObject("user authentication received");
	        System.out.println("SENT: user authentication received");
	        System.out.println(userAuthenticated);
	        }catch(IOException e) {
	        	System.err.println("Error communicating with server: " + e.getMessage());
	        }
        }
        
        if (medicUsername != null) {
            try {
                FileInputStream fis10 = new FileInputStream("../Medicos/"+ medicUsername + ".keystore.jks");
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                char[] password2 = "123456".toCharArray();
                ks.load(fis10, password2);


                if (ks.containsAlias(utentUsername)) {
                    System.out.println("Certificate is in the keystore.");
                } else {
                    FileInputStream certInputStream = new FileInputStream("../Certificados/" + utentUsername + ".cert.crt");
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Certificate cert = certificateFactory.generateCertificate(certInputStream);
                    certInputStream.close();


                    ks.setCertificateEntry(utentUsername, cert);


                    try (FileOutputStream keyStoreOutputStream = new FileOutputStream("../Medicos/"+ medicUsername + ".keystore.jks")) {
                        ks.store(keyStoreOutputStream, "123456".toCharArray());
                    }

                    System.out.println("Certificate not found in the keystore.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        for (File file :fileList) {
        	try {
        		  String fileName = file.getName();
        		  out.writeObject(fileName);
        		  out.flush();
        		  System.out.println("SENT: File name - " + fileName); // Include filename in message

        		  String response3 = (String) in.readObject();
        		  System.out.println("RECV: " + response3);
    		} catch (IOException e) {
    			System.err.println("Error communicating with server: " + e.getMessage());
    		} catch (ClassNotFoundException e) {
    			System.err.println("Error class not found: " + e.getMessage());
			}

            
            
            byte[] buffer = new byte[1024];
            int bytesRead;

            
        	switch (action) {
        		case "-sc":
        			try {
        				boolean cont = (boolean) in.readObject();
        				if(cont) {
	            			byte[] encryptedBuffer = CifraHibrida.encrypt(medicUsername, file, utentUsername, ".cifrado", password); 
	                        out.write(encryptedBuffer);
	                        out.flush();
	                        System.out.println("SENT: Hybrid encrypted Key ");
	                        
	                		String response4 = (String) in.readObject();
	        			    System.out.println("RECV: " + response4);
	                        
	        			    File outputFile1 = new File(file.getName() + ".cifrado");
	        			    
	                        FileInputStream Efis = new FileInputStream(outputFile1);
	                        
	            			long fileSize1 = outputFile1.length();
	            			out.writeObject(fileSize1); 
	            			out.flush();
	            			System.out.println("SENT: File Size");
	            			String response = (String) in.readObject();
	            			
	            			System.out.println("RECV: " + response);
	                        
	                        while  ((bytesRead = Efis.read(buffer)) > 0) {
	                        	out.write(buffer, 0, bytesRead);
	                            out.flush();
	                        }
	            			Efis.close();
	            			System.out.println("SENT: Hybrid encrypted file ");
	            			
	                		String response5 = (String) in.readObject();
	        			    System.out.println("RECV: " + response5);
        				}else {
        					System.err.println("File already exists in the server");
        				}
        			} catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
                    break;
        		case "-sa":
        			try {
        				boolean cont = (boolean) in.readObject();
        				if(cont) {
		        			File outputFile = new File(file.getName() + ".assinatura." + medicUsername);
		        			Assinatura.assinar(utentUsername, file, outputFile, password);
		        			FileInputStream Fis = new FileInputStream(outputFile);
		        			FileInputStream Sig = new FileInputStream(file);
		        			
		        			long fileSize2 = outputFile.length();
		        			out.writeObject(fileSize2); 
		        			out.flush();
		        			System.out.println("SENT: File Size");
		        			String response7 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response7);
		        			
		    			    long fileSize3 = file.length();
		    			    out.writeObject(fileSize3);
		        			out.flush();
		        			
		        			System.out.println("SENT: File Size");
		        			String response8 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response8);
		        			
		        			while  ((bytesRead = Fis.read(buffer)) > 0) {
		                        out.write(buffer, 0, bytesRead);
		                        out.flush();
		                    }
		        			Fis.close();
		        			
		        			System.out.println("SENT: Signature");
		        			String response6 = (String) in.readObject();
		        			
		    			    System.out.println("RECV: " + response6);
		        			    			    
		    			    while  ((bytesRead = Sig.read(buffer)) > 0) {
		                        out.write(buffer, 0, bytesRead);
		                        out.flush();
		                    }
		                    Sig.close();
		                    
		                    System.out.println("SENT: Signed file");
		                    
		                    String response9 = (String) in.readObject();
		    			    System.out.println("RECV: " + response9);
        				}else {
        					System.err.println("File already exists in the server");
        				}
        			}catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
                    break;
        		case "-se":
        			try {
        				boolean cont = (boolean) in.readObject();
        				if(cont) {
		        			File outputFile2 = new File(file.getName() + ".assinatura." + medicUsername + ".seguro");
		        			Assinatura.assinar(utentUsername, file, outputFile2, password);
		        			
		        			long fileSize4 = outputFile2.length();
		        			out.writeObject(fileSize4); 
		        			out.flush();
		        			System.out.println("SENT: File Size");
		        			String response10 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response10);
		        			
		        			File encryptedFile = new File(file.getName() + ".seguro");
		        			
		        			byte[] encryptedKey = CifraHibrida.encrypt(medicUsername, file, utentUsername, ".seguro", password);
		        			
		        			long fileSize5 = encryptedFile.length();
		        			System.out.println(fileSize5);
		        			out.writeObject(fileSize5); 
		        			out.flush();
		        			System.out.println("SENT: File Size");
		        			String response12 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response12);
		        			
		        			FileInputStream encryptedSig = new FileInputStream(outputFile2);
		                    while  ((bytesRead = encryptedSig.read(buffer)) > 0) {
		                        out.write(buffer, 0, bytesRead);
		                        out.flush();
		                    }
		                    System.out.println("SENT: Signature ");
		        			String response11 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response11);
		        			 
		                    
		        			out.write(encryptedKey);
		                    out.flush();
		                    System.out.println("SENT: Encryption key ");
		                    
		        			FileInputStream Efis2 = new FileInputStream(encryptedFile);
		                    while  ((bytesRead = Efis2.read(buffer)) > 0) {
		                        out.write(buffer, 0, bytesRead);
		                        out.flush();
		                    }
		                    System.out.println("SENT: Encrypted file ");
		                    String response13 = (String) in.readObject();
		        			
		        			System.out.println("RECV: " + response13);
		                    
		        			Efis2.close();
        				}else {
        					System.err.println("File already exists in the server");
        				}
        			}catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
        			break;
        		case "-g":
        			try {
        				String response14 = (String) in.readObject();
        	            System.out.println("RECV: " + response14);
        	            
        	            if(response14.equals("")) {
        	            	System.out.println("File with name " + file.getName() + " not found");
        	            }
        	            
        	            else if (response14.equals("assinado") || response14.equals("seguro")) {
	        	            Boolean response15 = (Boolean) in.readObject();
	        	            System.out.println("RECV: " + response15);
	        	        }
      
			    		else if(response14.equals("cifrado")) {
			    			byte[] buf = new byte[1024];
			    						    			
			    			FileOutputStream fos = null;
							try {
								fos = new FileOutputStream(file);
							} catch (IOException e) {
								System.err.println("Error communicating with server: " + e.getMessage());
							}
			    			
			    			long fileSize6 = (Long) in.readObject(); 
							System.out.println("RECV: File Size");
	
							try {
								out.writeObject("File Size Received");
							} catch (Exception e) {
								e.printStackTrace();
							}
						    System.out.println("SENT: File Size Received");
						    
						    

						    
						    long totalBytesRead1 = 0;
						    
						    while (totalBytesRead1 < fileSize6) {
						    	bytesRead = in.read(buf, 0, (int) Math.min(buf.length, fileSize6 - totalBytesRead1));
						    	if (bytesRead > 0) {
								    fos.write(buf, 0, bytesRead);
								    fos.flush();
								    totalBytesRead1 += bytesRead;
						    	} else {
						    		break;
						    	}
							}
						    fos.close();
						    
						    System.out.println("RECV: Signature");
				    		
						    out.writeObject("Signature Received");
						    System.out.println("SENT: Signature Received");
			    		}
        			} catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class now found: " + e.getMessage());
					}
        			break;
        		case "-au":
        			try {
                    	
                    	if (file.exists()) {
                    		FileInputStream certStream = new FileInputStream(file);
                    		
                        	out.writeObject(file.length());
                      	  	out.flush();
                      	  	System.out.println("SENT: " + file.length() + " as certificate size");
                      	  	
                      	  	Boolean found = (Boolean)in.readObject();
                      	  	
                      	  	if(!found) {
	                      	  	String response1 = (String) in.readObject();
	                      	  	System.out.println("RECV: " + response1);
	                      	  	
	                      	  	while  ((bytesRead = certStream.read(buffer)) > 0) {
	                              out.write(buffer, 0, bytesRead);
	                              out.flush();
	                      	  	}
	                      	  	
	                      	  	System.out.println("SENT: Certificate ");
	              				String response11 = (String) in.readObject();
	              			
	              				System.out.println("RECV: " + response11);
	              				certStream.close();
                      	  	}else {
                      	  		System.err.println("User with the specified name already exists.");
                      	  	}
                    	}
                    	else {
                    		throw new FileNotFoundException("File not found: " + file.getName());
                    	}
                	}catch(IOException e) {
                		//TODO
                		System.err.println(e);
                	}
        	}
    	}
        try {
			out.close();
		} catch (IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		}
        try {
			socket.close();
		} catch (IOException e) {
			System.err.println("Error communicating with server: " + e.getMessage());
		}
    }
}


