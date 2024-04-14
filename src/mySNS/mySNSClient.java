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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class mySNSClient {

    public static void main(String[] args) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException {
        Socket socket = null;
		try {
			socket = new Socket(args[1], 23456);
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
        
        String medicUsername = null;
        String utentUsername = null;
        String[] fileNames = null;
        String action = null;
        String password = null;
        
        switch (args[2]){
        	case "-m":
        		  try {
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
        			String newUserPass = args[4];
        			String newUserCertificateName = args[5];
        			action = "-au";
        			out.writeObject(action);
        			System.out.println("SENT: -au");
        			
        			String response4 = (String) in.readObject();
        		    System.out.println("RECV: " + response4);
        		    
        		    //Send the username
        		    out.writeObject(newUsername);
        			System.out.println("SENT: username " + newUsername);
        			
        			String response5 = (String) in.readObject();
        		    System.out.println("RECV: " + response5);
        		    
        		    //Send the password
        		    out.writeObject(newUserPass);
        			System.out.println("SENT: username " + newUserPass);
        			
        			String response6 = (String) in.readObject();
        		    System.out.println("RECV: " + response6);
        		    
        		    //Send the certificate
        		    
        		}catch(IOException e) {
        			System.err.println("Error communicating with server: " + e.getMessage());
        		} catch (ClassNotFoundException e) {
        			System.err.println("Error reading response: " + e.getMessage());
				}
        }
        if(args[4].equals("-p")) {
				password = args[5];
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

        		    String response4 = (String) in.readObject();
        		    System.out.println("RECV: " + response4);

        		    fileNames = Arrays.copyOfRange(args, 5, args.length);
        		} catch (IOException e) {
        		    System.err.println("Error communicating with server: " + e.getMessage());
        		} catch (ClassNotFoundException e) {
        			System.err.println("Error reading response: " + e.getMessage());
        		}
        		break;
        	}
        
        if (args.length > 7) {
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
        
        
        ArrayList<File> fileList = new ArrayList<File>();
    
        
        for (String fileName : fileNames) {
        	File file = new File(fileName);
           
            if (!file.exists() && !action.equals("-g")) {
                System.err.println("Error: File " + fileName + " not found!");
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
        			} catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
                    break;
        		case "-sa":
        			try {
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
        			}catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
                    break;
        		case "-se":
        			try {
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
        			}catch(IOException e) {
        				System.err.println("Error communicating with server: " + e.getMessage());
        			} catch (ClassNotFoundException e) {
        				System.err.println("Error class not found: " + e.getMessage());
					}
        			break;
        		case "-g":
        			try {
	        			String[] fileState = file.getName().split("\\.");
			    		if(fileState[fileState.length - 1].equals("assinado") || fileState[fileState.length - 1].equals("seguro")) {
	        	            Boolean response14 = (Boolean) in.readObject();
	        	            System.out.println("RECV: " + response14);
	        	        }
			    		else if(fileState[fileState.length - 1].equals("cifrado")) {
			    			byte[] buf = new byte[1024];
			    			
			    			File file2 = new File(fileState[0] + "." + fileState[1]);
			    			
			    			FileOutputStream fos = null;
							try {
								fos = new FileOutputStream(file2);
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
