import java.io.*;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** @author Mark Erickson
 *  CS 460 Final Project
 *  Sender
 */ 
public class Sender {

	// This is the AES algorithm to be used. It uses AES with cipher block chaining that uses an initialization vector
	// to start the algorithm and guarantee all patterns in the ciphertext are eliminated.
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding"; 

	private static final String ALGO = "AES";
	
	private static final String ALGORITHMRSA = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";
	
	private static final String PUBLIC_KEY_FILE = "Public_Key.txt";
	
	private static final String MACALGORITHM = "HmacSHA512";
	
	private static final String HMAC_KEY_FILE = "HMAC_Key.txt";
	
	private static final byte[] HMAC = {-96, -60, -61, 17, 115, -92, 59, 33, 88, -93, 43, -108, 59, -70, 86, 92, 0, 27, -15, 98, 71, -59,-39,
            -128, 104, -69, -25, -121, 126, -90, 64, 17, 27, 51, 29, -86, -9, 5, 74, -7, 58, 13, -117, -100, 89,
            -90, 125, -25, -85,-52, 73, -29, 10, -14, -21, -7, 48, 79, 112, 7, 102, -74, -109, 41};


	public static void main(String args[]) throws Exception{
		Scanner keyBoard = new Scanner(System.in);
		String input;
		byte[] data = null; //Holds user input either from created file or passed file.
		System.out.print("Do you want to encrypt a create or use an existing file?\n1:Create File\n2:Use Existing File\n");
		input = keyBoard.nextLine();
		try{
			int inputSelected = Integer.parseInt(input);
			if (inputSelected == 1){ //User chose to create their own file.
				String fileName = "";
				System.out.print("Enter the name of the file you want to create: ");
				fileName = keyBoard.nextLine();
				String fileLine = "";
				try {
					FileWriter fWriter = new FileWriter(fileName,true);
					PrintWriter pw = new PrintWriter(fWriter);
					System.out.println("Enter the text you want to encrypt and enter -1 on a line to stop.");
					while (!fileLine.equals("-1")){
						fileLine = keyBoard.nextLine();
						if (!fileLine.equals("-1")){
							pw.println(fileLine);
						}
					}
					pw.close();
					File file = new File(fileName);
					data = Files.readAllBytes(file.toPath()); //Read data from file.
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				}
			}
			else if (inputSelected == 2){ //User chooses to use existing file
				String fileName = "";
				System.out.print("Enter a fileName: ");
				fileName = keyBoard.nextLine();
				try {
					File file = new File(fileName);
					data = Files.readAllBytes(file.toPath());
				} catch (Exception e) {
					System.out.println("The file was not found.");
					System.exit(0);
				}
			}
		} catch(NumberFormatException e){
			System.out.println("Command not recognized.");
			System.exit(0);
		}
		keyBoard.close();
		
		

		// Creating the AES key.
		KeyGenerator keyGen = KeyGenerator.getInstance(ALGO); // Uses the KeyGenerator class's getInstance method to get a random symmetric key for AES.
		keyGen.init(256); // This initializes the KeyGenerator object to use a 256 bit AES key.
		SecretKey key = keyGen.generateKey();
		
		// RSA encrypting the AES shared key.
		byte[] cipherTextAESKey = null;
		Cipher RSACipher = Cipher.getInstance(ALGORITHMRSA); // The type of RSA to be used.
		ObjectInputStream pubKeyIS = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE)); //Getting the receiver's public key from the file.
		PublicKey publicKey = (PublicKey) pubKeyIS.readObject(); //Getting public key from file.
		RSACipher.init(Cipher.WRAP_MODE, publicKey); // Initialize the cipher in wrap mode.
		cipherTextAESKey = RSACipher.wrap(key); //Wrapping the AES key with the receiver's RSA public key.
		pubKeyIS.close();
		
		// Encrypting the file with AES 
		Cipher AesCipher = Cipher.getInstance(ALGORITHM);
		byte[] initVector = new byte[16]; // Generating initialization vector.
		SecureRandom random = new SecureRandom(); //Using Java's secure library random function.
		random.nextBytes(initVector); // Fills the initialization vector with random bytes using a random seed. 
		IvParameterSpec iVParameters = new IvParameterSpec(initVector);
		
		//Saving the initialization vector in a file in plain text. Does not have to be secret only random.
		FileOutputStream ivOut = new FileOutputStream(new File("Init_Vector.txt"));
		ivOut.write(iVParameters.getIV());
		ivOut.close();
		
		AesCipher.init(Cipher.ENCRYPT_MODE, key, iVParameters);
		byte[] encVal = AesCipher.doFinal(data);

		
		// Creating HMAC
		
		/* This code used to generate the HMAC key at random. 
		//KeyGenerator HMACKeyGen = KeyGenerator.getInstance(MACALGORITHM);
		//SecretKey HMACKey = HMACKeyGen.generateKey(); //Generates the key for the HMAC
		*/ 
		
		SecretKeySpec createKey = new SecretKeySpec(HMAC,MACALGORITHM);
		SecretKey HMACKey = createKey;
		Mac hMac = Mac.getInstance(HMACKey.getAlgorithm()); //Returns a mac object that uses the specified MAC algorithm.
		hMac.init(HMACKey);
		
		// Exporting the HMAC key to a file.
		File HMACKeyFile = new File(HMAC_KEY_FILE);
		ObjectOutputStream hMACKeyOS = new ObjectOutputStream(new FileOutputStream(HMACKeyFile));
	    hMACKeyOS.writeObject(HMACKey.getEncoded());
	    hMACKeyOS.close();
	    
	    //Concatenates the message ciphertext and the wrapped AES key to be used in the HMAC digest.
		byte[] cipherTextBytes = new byte[encVal.length + cipherTextAESKey.length];
		System.arraycopy(cipherTextAESKey, 0, cipherTextBytes, 0, cipherTextAESKey.length);
		System.arraycopy(encVal,0,cipherTextBytes,cipherTextAESKey.length,encVal.length);
		
		//System.arraycopy(encVal,0, cipherTextBytes,0,encVal.length);
		//System.arraycopy(cipherTextAESKey, 0, cipherTextBytes, encVal.length, cipherTextAESKey.length);
		
		hMac.update(cipherTextBytes); 

		FileOutputStream createFile = new FileOutputStream(new File("encrypted_output.txt")); // Creating a file for output.
		createFile.write(hMac.doFinal()); // Putting the mac in first.
		createFile.write(cipherTextAESKey); // Now the AES key encrypted with RSA and is put into the file.
		createFile.write(encVal); // The cipher text encrypted with AES is added.
		createFile.close();
	}
}