package com.company;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {
            AES_ENCRYPTION aes_encryption = new AES_ENCRYPTION();
            Scanner scanner = new Scanner(System.in);


            while(true) {

                System.out.println("Enter your string :");
                String input_string = scanner.nextLine();
                aes_encryption.init();
                String signature = aes_encryption.encrypt(input_string);
                System.out.println("Generated signature : "+signature);
                System.out.println("Do you need send ? [Y-Yes , N-No ] :");
                String answer = scanner.nextLine();
                if(answer.equals("Y")){
                    boolean verified = false;
                    while (!verified) {
                        System.out.println("Enter the signature:");
                        try {
                            String secret_signature = scanner.nextLine();
                            String decrypt_string = aes_encryption.decrypt(secret_signature);

                            if (input_string.equals(decrypt_string)) {
                                System.out.println("verified");
                                verified = !verified;
                            } else {
                                System.out.println("invalid signature");
                            }
                        }  catch (Exception exception) {
                            System.out.println("invalid signature");
                        }
                    }
                    System.out.println("Do you need to exit? [Y-Yes, N-No] :");
                    answer = scanner.nextLine();
                    if(answer.equals("Y")){
                        return;
                    }

                }

            }

        } catch (Exception exception) {
            System.out.println("Exception :"+exception.getMessage());
        }
    }
}

class AES_ENCRYPTION  {

    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private final int KEY_SIZE = 128;
    private SecretKey key;

    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }

    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

}
