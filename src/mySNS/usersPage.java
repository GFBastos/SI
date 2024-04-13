package mySNS;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class usersPage {
	
	private static usersPage instance;
	private File users;
	private static final int SALT_LENGTH = 16;
	
	private usersPage() {
		 this.users = new File("users.txt");
	}
	
	public static usersPage getInstance() {
        if (instance == null) {
            instance = new usersPage();
        }
        return instance;
    }
	
	public void newUser(String name, String password) throws NoSuchAlgorithmException {
		try {
			Boolean found = checkName(name);
			if(!found) {
				String[] userSaltPassword = hashPassword(password);
				String salt = userSaltPassword[0];
				String hashedPassword = userSaltPassword[1];
				BufferedWriter usersList = new BufferedWriter(new FileWriter(this.users, true));
				String line = name + ";"+ salt +";" + hashedPassword;
	            usersList.write(line);
	            usersList.newLine(); 
				usersList.close();
				System.out.println(String.format("%u written to the users file successfully.", name));
				
				File directory = new File("utilizadores/" +  name);
				directory.mkdir();
				System.out.println(String.format("New file for user %n created", name));
			}else {
				System.err.println("User with same username already exists!");
			}
			
		}catch(IOException e) {
			System.err.println(e);
		}
	}
	
	public Boolean checkName(String name) {
		try {
		      Scanner scanner = new Scanner(this.users);
		      boolean found = false;

		      // Read the file line by line
		      while (scanner.hasNextLine()) {
		        String line = scanner.nextLine();
		        String currentLineName = line.split("//;")[0];
		        if (currentLineName.equals(name)) {
		          found = true;
		          break; 
		        }
		      }

		      scanner.close();
		      return found;
		}catch(FileNotFoundException e) {
			System.err.println("The users file hasnt been created yet");
			return false;
		}
	}
	
	public static String[] hashPassword(String password) throws NoSuchAlgorithmException {
		try {
			byte[] salt = generateSalt();
			
			MessageDigest md = MessageDigest.getInstance("SHA-256");
	        md.update(salt);
	        byte[] hashedPassword = md.digest(password.getBytes());
	
	        String encodedHash = Base64.getEncoder().encodeToString(hashedPassword);
	        String encodedSalt = Base64.getEncoder().encodeToString(salt);
	
	        String[] encodedResult = {encodedSalt, encodedHash};
	        return encodedResult;
		}catch(NoSuchAlgorithmException e) {
			System.err.println("SHA-256 Algorithm Not Found");
			throw e;
		}
		
	}
	
	public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
}
