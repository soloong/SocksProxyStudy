package com.tianwt.rx.socks;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class MyRsa {
	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";
 
	/**
	 * String to hold the name of the private key file.
	 */
	public static final String PRIVATE_KEY_FILE = "D:/rsa/pkcs8_priv.pem";
 
	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "D:/rsa/public.key";
 
	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}
 
	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);
 
		} catch (Exception ex) {
			ex.printStackTrace();
		}
 
		return new String(dectyptedText);
	}
 
	public static void test() {
		String s = "Hello world";
		try {
			BufferedReader privateKey = new BufferedReader(new FileReader(
					PRIVATE_KEY_FILE));
			BufferedReader publicKey = new BufferedReader(new FileReader(
					PUBLIC_KEY_FILE));	
			String strPrivateKey = "";
			String strPublicKey = "";
			String line = "";
			while((line = privateKey.readLine()) != null){
				strPrivateKey += line;
			}
			while((line = publicKey.readLine()) != null){
				strPublicKey += line;
			}
			privateKey.close();
			publicKey.close();
 
			// 私钥需要使用pkcs8格式的，公钥使用x509格式的
			String strPrivKey = strPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "");				
			String strPubKey = strPublicKey.replace("-----BEGIN PUBLIC KEY-----", "")
					.replace("-----END PUBLIC KEY-----", "");
			//System.out.print(strPrivKey);
			//System.out.println(strPubKey);	
			byte [] privKeyByte = Base64.getDecoder().decode(strPrivKey);
			byte [] pubKeyByte = Base64.getDecoder().decode(strPubKey);
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyByte);
			//PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(pubKeyByte);
 
			//X509EncodedKeySpec 	privKeySpec = new X509EncodedKeySpec(privKeyByte);
			X509EncodedKeySpec 	pubKeySpec = new X509EncodedKeySpec(pubKeyByte);
 
			KeyFactory kf = KeyFactory.getInstance("RSA");
 
			PrivateKey privKey = kf.generatePrivate(privKeySpec);
			PublicKey pubKey = kf.generatePublic(pubKeySpec);
 
			byte [] encryptByte = encrypt(s, pubKey);
			System.out.println(decrypt(encryptByte, privKey));
 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}