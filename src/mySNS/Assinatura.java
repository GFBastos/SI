package mySNS;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Assinatura {

	public static void assinar(String user, File inputFile, File outputFile)   {
		try {
			String passwrd = "123456";
		    FileInputStream fis = new FileInputStream(inputFile);
		    FileOutputStream sfos = new FileOutputStream(outputFile);
		    
		    FileInputStream kis = new FileInputStream("../Utilizadores/"+ user + "/"  + user + ".keystore.jks");
		    KeyStore kstore = KeyStore.getInstance("PKCS12");
		    kstore.load(kis, passwrd.toCharArray());
		    
		    Key privateKey = kstore.getKey(user, passwrd.toCharArray()); 
		    PrivateKey pk = (PrivateKey) privateKey;
		    
		    Signature signer = Signature.getInstance("MD5withRSA");
		    signer.initSign(pk);
	
		    // Update the Signature object with the data to be signed
		    byte[] buffer = new byte[16]; 
		    int bytesRead = fis.read(buffer);
	
		    while (bytesRead > 0) {
		        signer.update(buffer, 0, 1);
		        
		        bytesRead = fis.read(buffer);
		    }
		    sfos.write(signer.sign());
		    sfos.close();
		    fis.close();
		} catch (NoSuchAlgorithmException e) {
	        System.err.println("Algorithm not found: " + e.getMessage());
	    } catch (CertificateException e) {
	        System.err.println("Certificate exception: " + e.getMessage());
	    } catch (IOException e) {
	        System.err.println("IO Exception occurred: " + e.getMessage());
	    } catch (KeyStoreException e) {
	        System.err.println("KeyStore exception: " + e.getMessage());
	    } catch (UnrecoverableKeyException e) {
	        System.err.println("Unrecoverable key: " + e.getMessage());
	    } catch (InvalidKeyException e) {
	        System.err.println("Invalid key: " + e.getMessage());
	    } catch (SignatureException e) {
	        System.err.println("Signature exception: " + e.getMessage());
	    }
	}
	
	public static boolean verificar(File inputContent, File inputCertificate, String user) {
	    FileInputStream fis = null;
	    FileInputStream fisign = null;
	    FileInputStream kis = null;

	    try {
	        fis = new FileInputStream(inputContent);
	        fisign = new FileInputStream(inputCertificate);
	        kis = new FileInputStream("Utilizadores/" + user + "/" + user + ".keystore.jks");

	        KeyStore kstore = KeyStore.getInstance("PKCS12");
	        kstore.load(kis, "123456".toCharArray());

	        Certificate myCertificate = kstore.getCertificate(user);
	        PublicKey pubK = myCertificate.getPublicKey();
	        Signature signer = Signature.getInstance("MD5withRSA");
	        signer.initVerify(pubK);

	        byte[] buffer = new byte[16];
	        int bytesRead = fis.read(buffer);
	        
	        while (bytesRead != -1) {
	            signer.update(buffer, 0, 1);
	            
	            bytesRead = fis.read(buffer);
	        }

	        byte[] signInit = new byte[256];
	        fisign.read(signInit);

	        return signer.verify(signInit);

	    } catch (FileNotFoundException e) {
	        System.err.println("Error: Keystore file not found. Please check the path and try again.");
	    } catch (IOException e) {
	        System.err.println("An IO error occurred while accessing the keystore. Please ensure proper file permissions and try again.");
	    } catch (NoSuchAlgorithmException e) {
	        System.err.println("The requested algorithm for keystore access is unavailable. Please contact your system administrator.");
	    } catch (CertificateException e) {
	        System.err.println("A certificate issue was encountered. The certificate might be invalid or corrupt.");
	    } catch (InvalidKeyException e) {
	        System.err.println("The provided key is invalid. Please verify the keystore password or credentials.");
	    } catch (SignatureException e) {
	        System.err.println("A signature exception occurred. This might indicate a problem with the certificate's signature.");
	    } catch (KeyStoreException e) {
	        System.err.println("A keystore exception occurred. This could be due to an invalid keystore format or incorrect password.");
	    }
	    return false;
	}
}
