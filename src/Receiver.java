import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
	 
    private static final String MACALGORITHM = "HmacSHA512";
	
	private static final String PRIVATE_KEY_FILE = "Private_Key.txt";
	
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	
	private static final String ALGORITHMRSA = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";
	
	private static final String ALGO = "AES";
	
	private static final byte[] HMAC = {-96, -60, -61, 17, 115, -92, 59, 33, 88, -93, 43, -108, 59, -70, 86, 92, 0, 27, -15, 98, 71, -59,-39,
			                            -128, 104, -69, -25, -121, 126, -90, 64, 17, 27, 51, 29, -86, -9, 5, 74, -7, 58, 13, -117, -100, 89,
			                            -90, 125, -25, -85,-52, 73, -29, 10, -14, -21, -7, 48, 79, 112, 7, 102, -74, -109, 41};
	
	public static void main(String[] args) throws Exception{
		
		//Retrieving MAC from file.
		FileInputStream readFile = new FileInputStream(new File("encrypted_output.txt"));
		byte[] hMac = new byte[64]; //Reading MAC from top of file.
		readFile.read(hMac);
		readFile.close();
		
		//Retrieving HMAC key
		//FileInputStream readKey = new FileInputStream(new File(HMAC_KEY_FILE));
		//byte[] key = new byte[64];
		//readKey.read(key);
		//SecretKeySpec createKey = new SecretKeySpec(key,MACALGORITHM);
		
		SecretKeySpec createKey = new SecretKeySpec(HMAC,MACALGORITHM); //Creating HMAC key from given byte array.
		SecretKey hMacKey = createKey;
		//readKey.close();
				
		Mac mac = Mac.getInstance(hMacKey.getAlgorithm()); //Getting an instance of the HMAC SHA-512 key.
		mac.init(hMacKey); //Initalize HMAC Key.
		FileInputStream readFileForMAC = new FileInputStream(new File("encrypted_output.txt"));
		byte[] macTest = new byte[readFileForMAC.available() - 64]; //Size of file minus the MAC.
		readFileForMAC.skip(64); //Skip the MAC
		readFileForMAC.read(macTest); //Read bytes from file into byte array.
		mac.update(macTest);
		byte[] calculatedMac = mac.doFinal(); //Calculate the MAC.
		boolean macAgreement = true;
		if (calculatedMac.length != hMac.length){
			macAgreement = false;
			System.out.println("The MACs were different lengths");
		}
		else{
			for (int i=0; i<hMac.length;i++){
				if (hMac[i] != calculatedMac[i]){
					macAgreement = false;
					break;
				}
			}
		}
		System.out.println("Are the MACs the same: " + macAgreement);
		readFileForMAC.close();
		
		// Using RSA to unwrap the key.
		Cipher RSACipher = Cipher.getInstance(ALGORITHMRSA); // The type of RSA to be used.
		ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE)); //Getting the receiver's private key from the file.
		PrivateKey privateKey = (PrivateKey) privateKeyIS.readObject(); // Private Key object
		privateKeyIS.close();
		RSACipher.init(Cipher.UNWRAP_MODE, privateKey); // Initialize the cipher in unwrap mode.
		byte[] AESKeyBytes = new byte[512]; // Length of AES key.
		FileInputStream readFileForAESKey = new FileInputStream(new File("encrypted_output.txt"));
		readFileForAESKey.skip(64); //Skip past the MAC to get to RSA encrypted AES key.
		
		readFileForAESKey.read(AESKeyBytes); // The AES key is between the HMAC which is 88 bytes long and the cipher text.
		SecretKey AESKey = (SecretKey) RSACipher.unwrap(AESKeyBytes, ALGO, Cipher.SECRET_KEY);
		readFileForAESKey.close();
		
		// Decrypting the cipher text with the AES key
		Cipher AES = Cipher.getInstance(ALGORITHM);
		
		//Reading initialization vector from a file.
		byte[] initVector = new byte[16];
		FileInputStream iv = new FileInputStream(new File("Init_Vector.txt"));
		iv.read(initVector);
		iv.close();
		IvParameterSpec iVPS = new IvParameterSpec(initVector);
		
		//Decoding ciphertext 
		AES.init(Cipher.DECRYPT_MODE, AESKey, iVPS); //Initialize object to decrypt the message using the AES key.
		FileInputStream readFileForAES = new FileInputStream(new File("encrypted_output.txt"));
		byte[] cipherText = new byte[readFileForAES.available() - 576]; //Gets the ciphertext portion of the file.
		readFileForAES.skip(576); //Skips the MAC and RSA encrypted AES key.
		readFileForAES.read(cipherText); //Read ciphertext from file to byte array.
		readFileForAES.close();
		
		byte[] plainText = AES.doFinal(cipherText); //Getting the plaintext from the AES object.
		FileOutputStream decryptedText = new FileOutputStream(new File("decrypted_text.txt")); 
		decryptedText.write(plainText); //Writing the plaintext to a file.
		decryptedText.close();
		
	}
}
