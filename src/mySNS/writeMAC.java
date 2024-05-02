package mySNS;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class writeMAC {
	public static void init(String pass) {
		try {
			FileInputStream fis = new FileInputStream("users.txt");
			FileOutputStream fos = new FileOutputStream("users.mac");
			
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
			
			fos.write(mac);
			fos.close();
			fis.close();
		}catch(IOException e) {
			System.err.println(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
