package mySNS;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Cifra {

    public static byte[] cifrar(File file, String extension) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException{
	    try {
	    	//gerar uma chave aleatoria para utilizar com o AES
		    KeyGenerator kg = KeyGenerator.getInstance("AES");
		    kg.init(128);
		    SecretKey key = kg.generateKey();
		
		    Cipher c = Cipher.getInstance("AES");
		    c.init(Cipher.ENCRYPT_MODE, key);
		
		    FileInputStream fis;
		    FileOutputStream fos;
		    CipherOutputStream cos;
		    
		    fis = new FileInputStream(file);
		    fos = new FileOutputStream(file.getName() + extension);
		
		    cos = new CipherOutputStream(fos, c);
		    byte[] b = new byte[128];  
		    int i = fis.read(b);
		    while (i != -1) {
		        cos.write(b, 0, i);
		        i = fis.read(b);
		    }
		    cos.close();
		    fis.close();
		    
		    byte[] keyEncoded = key.getEncoded();
		    FileOutputStream kos = new FileOutputStream(file.getName() + ".chave_secreta");
		    kos.write(keyEncoded);
		    kos.close();
		    return keyEncoded;
        } catch (SocketException e) {
            System.err.println("Connection aborted by the host machine." + e.getMessage());
            throw e;
        } catch (NoSuchPaddingException e) {
            System.out.println("Padding mechanism not found: " + e.getMessage());
            throw e;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key: " + e.getMessage());
            throw e;
        } catch (IOException e) {
            System.err.println("IO Exception occurred." + e.getMessage());
            throw e;
        }

    }

    
    public static void decifrar(String fileName, String user, SecretKeySpec secretKey){
    	try {
	    	//c.init(Cipher.DECRYPT_MODE, keySpec2);    //SecretKeySpec é subclasse de secretKey
		    Cipher c = Cipher.getInstance("AES");
		    c.init(Cipher.DECRYPT_MODE, secretKey);
		    
		    
		    FileInputStream encryptedFileInputStream = new FileInputStream("Utilizadores/" + user + "/" + fileName);
		    String[] fileNames = fileName.split("\\.");
		    FileOutputStream decryptedFileOutputStream = new FileOutputStream("decrypted_" + fileNames[0] + "." + fileNames[1]);
		    CipherInputStream cis = new CipherInputStream(encryptedFileInputStream, c);
		    
		    byte[] buffer = new byte[128];
		    int bytesRead;
		    while ((bytesRead = cis.read(buffer)) > 0) {
		    	System.out.println(bytesRead);
		        decryptedFileOutputStream.write(buffer, 0, bytesRead);
		    }
		    
		    cis.close();
		    decryptedFileOutputStream.close();
		    }catch(NoSuchAlgorithmException nsae) {
	    		System.err.println("Error no such algorithm: " + nsae.getMessage());
		    }catch(NoSuchPaddingException nspe) {
		    	System.err.println("Error no such padding: " + nspe.getMessage());
		    }catch(InvalidKeyException ike) {
		    	System.err.println("Error Invalid Key: " + ike.getMessage());
		    }catch(IOException ioe) {
	    		System.err.println("IO Exception occurred." + ioe.getMessage());
		}
    }
}

