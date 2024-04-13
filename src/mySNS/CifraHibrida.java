package mySNS;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CifraHibrida {

    public static  byte[] encrypt(String medic, File file, String alias, String extension) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException{
    	try {

	    	FileInputStream kis = new FileInputStream("../Medicos/" + medic + ".keystore.jks");
		    KeyStore kstore = KeyStore.getInstance("PKCS12");
		    kstore.load(kis, "123456".toCharArray());
		    
		    Certificate myCertificate = kstore.getCertificate(alias);
		    PublicKey pubK = myCertificate.getPublicKey();
		    
		    byte[] skEncoded = Cifra.cifrar(file, extension);
		    
		    SecretKey secretKey = new SecretKeySpec(skEncoded, 0, skEncoded.length, "AES");
		    							  
		    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
		    c.init(Cipher.WRAP_MODE, pubK);
		
		    byte[] encryptedSymmetricKey = c.wrap(secretKey);
		    
		    kis.close();
		    return encryptedSymmetricKey;
    	}catch (KeyStoreException e) {
    		  System.err.println("KeyStore exception: " + e.getMessage());
    		  throw e;
    		} catch (NoSuchAlgorithmException e) {
    		  System.err.println("Algorithm not found: " + e.getMessage());
    		  throw e;
    		} catch (CertificateException e) {
    		  System.err.println("Certificate exception: " + e.getMessage());
    		  throw e;
    		} catch (IOException e) {
    		  System.err.println("IO Exception occurred: " + e.getMessage());
    		  throw e;
    		} catch (InvalidKeyException e) {
    		  System.err.println("Invalid key: " + e.getMessage());
    		  throw e;
    		} catch (NoSuchPaddingException e) {
    		  System.err.println("Padding mechanism not found: " + e.getMessage());
    		  throw e;
    		} catch (IllegalBlockSizeException e) {
    		  System.err.println("Illegal block size: " + e.getMessage());
    		  throw e;
    		}

    }
    
    public static  void decrypt(String user, String passwrd, String fileName, byte[] encryptedSymmetricKey){
    	try {
	    	FileInputStream kis = new FileInputStream("Utilizadores/" + user + "/" + user + ".keystore.jks");
		    KeyStore kstore = KeyStore.getInstance("PKCS12");
		    kstore.load(kis, "123456".toCharArray());
		    
		    Key privateKey = kstore.getKey(user, passwrd.toCharArray()); 
		    
		    PrivateKey pk = (PrivateKey) privateKey;
	    	//byte[] keyEncoded2 - lido do ficheiro
	    	Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
	        c.init(Cipher.UNWRAP_MODE, pk);
	        Key secretKey = c.unwrap(encryptedSymmetricKey, "AES", Cipher.SECRET_KEY);
	        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
	        Cifra.decifrar(fileName, user, secretKeySpec);
    	} catch (KeyStoreException e) {
    		System.err.println("KeyStore exception: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algorithm not found: " + e.getMessage());
		} catch (CertificateException e) {
			System.err.println("Certificate exception: " + e.getMessage());
		} catch (IOException e) {
			System.err.println("IO Exception occurred: " + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			System.err.println("Unrecoverable key: " + e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding mechanism not found: " + e.getMessage());
		} catch (InvalidKeyException e) {
			System.err.println("Invalid key: " + e.getMessage());
		}
    }
    
    public static void retrieveCertificate(String pathToKeystore, String password, String aliasName){
        String keystoreFilePath = pathToKeystore;
        String keystorePassword = password;
        String alias = aliasName;
	  
        try {
            // Load the keystore
            FileInputStream fis = new FileInputStream(keystoreFilePath);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, keystorePassword.toCharArray());
            fis.close();

            // Retrieve the certificate
            Certificate certificate = keystore.getCertificate(alias);

            if (certificate != null) {
                System.out.println("Retrieved Certificate: " + certificate.toString());
            } else {
                System.out.println("Certificate not found for alias: " + alias);
            }
        }catch (NoSuchAlgorithmException e) {
        	System.err.println("Algorithm not found: " + e.getMessage());
    	} catch (CertificateException e) {
    	  System.err.println("Certificate exception: " + e.getMessage());
    	} catch (IOException e) {
    	  System.err.println("IO Exception occurred: " + e.getMessage());
    	} catch (KeyStoreException e) {
    	  System.err.println("KeyStore exception: " + e.getMessage());
    	}
    }
    
    public static boolean isKeyPairCompatible(PublicKey publicKey, PrivateKey privateKey) {
        try {
            // Sign and verify a message
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update("test message".getBytes());
            byte[] signatureBytes = signature.sign();

            signature.initVerify(publicKey);
            signature.update("test message".getBytes());
            boolean verified = signature.verify(signatureBytes);

            return verified;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
}

}
