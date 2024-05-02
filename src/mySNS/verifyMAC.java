package mySNS;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class verifyMAC {
	public static Boolean init(String pass) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		try {
			FileInputStream fis = new FileInputStream("users.txt");
			FileInputStream fisMAC = new FileInputStream("users.mac");
			
			byte[] password = pass.getBytes();
			SecretKey key = new SecretKeySpec(password, "HmacSHA256");
			
			Mac m = Mac.getInstance("HmacSHA256");
			m.init(key);
			
			byte[] b = new byte[16];
			int i = fis.read(b);
			
			while(i != -1) {
				m.update(b, 0, i);
				i = fis.read(b);
			}
			
			byte[] mac = m.doFinal();
			fis.close();
			
			// Tranformar bytes em String para ser mais facil de comprar 
			String sMAC = Base64.getEncoder().encodeToString(mac);
			
			byte[] macToBeVerified = new byte[fisMAC.available()];
			fisMAC.read(macToBeVerified);
			
			String b_macToBeVerified = Base64.getEncoder().encodeToString(macToBeVerified);
			
			if(sMAC.equals(b_macToBeVerified)) {
				return true;
			}
			
			return false;
			
		}catch(IOException e) {
			System.err.println(e.getMessage());
			throw e;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
	}
}
