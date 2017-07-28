import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class RsaKeyGenerator {
	
	private static final String ALGORITHM = "RSA";
	private static final String PRIVATE_KEY_FILE = "Private_Key.txt";
	private static final String PUBLIC_KEY_FILE = "Public_Key.txt";
	
	public static void main(String args[]){
		
		try{
		    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		    keyGen.initialize(4096); // 4096 bit RSA Key
		    KeyPair key = keyGen.generateKeyPair();
		    File prvKeyFile = new File(PRIVATE_KEY_FILE);
		    File pubKeyFile = new File(PUBLIC_KEY_FILE);
		    ObjectOutputStream prvKeyOS = new ObjectOutputStream(new FileOutputStream(prvKeyFile));
		    prvKeyOS.writeObject(key.getPrivate());
		    ObjectOutputStream pubKeyOS = new ObjectOutputStream(new FileOutputStream(pubKeyFile));
		    pubKeyOS.writeObject(key.getPublic());
		    prvKeyOS.close();
		    pubKeyOS.close();
		} catch(Exception e){
			e.printStackTrace();
		}
	}
}
