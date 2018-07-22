package com.tianwt.rx.http;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Class used to add the server's certificate to the KeyStore
 * with your trusted certificates.
 */
public class SSLCertInstaller {
	  
	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
	private static String KEYSTORE_PASSWORD = "WlZSak5GcFVUbTlsVjJSNg==";
	private static String KEYSTORE_PATH = "http_proxy_tls_clientTrust.cert";
	
    private static String toHexString(byte[] bytes) 
    {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    public static void main(String[] args) {
		try {
			createTrustCASocket("172.20.15.43", 1102);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	  
    public static SSLSocket createTrustCASocket(String host,int port) throws Exception {
    
        File file = new File(KEYSTORE_PATH);
        char[] password = KEYSTORE_PASSWORD.toCharArray(); 
        System.out.println("Loading KeyStore " + file + "...");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        if(!file.exists())
        {
        	ks.load(null, null);
        }else{
        	InputStream in = new FileInputStream(file);
        	ks.load(in, password);
        	in.close();
        }
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        CAX509TrustManager tm = new CAX509TrustManager(defaultTrustManager,ks,new String(password));
        
        context.init(null, new TrustManager[]{tm}, new SecureRandom());
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        
        X509Certificate certificate = (X509Certificate) ks.getCertificate(host);
        if(certificate!=null && CAX509TrustManager.isValid(certificate))
        {
        	return socket;
        }
	    try {
	            System.out.println("Starting SSL handshake...");
	            socket.startHandshake();
	            System.out.println("No errors, certificate is already trusted");
	            X509Certificate[] chain = tm.chain;
	        if (chain == null || chain.length==0) {
	            System.out.println("Could not obtain server certificate chain");
	            return null;
	        }
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return socket;
    }
    
    public static SSLSocket createTrustCASocket(Socket s) throws Exception {
        
        File file = new File(KEYSTORE_PATH);
        char[] password = KEYSTORE_PASSWORD.toCharArray(); 
        System.out.println("Loading KeyStore " + file + "...");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        if(!file.exists())
        {
        	ks.load(null, null);
        }else{
        	InputStream in = new FileInputStream(file);
        	ks.load(in, password);
        	in.close();
        }
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        CAX509TrustManager tm = new CAX509TrustManager(defaultTrustManager,ks,new String(password));
        
        context.init(null, new TrustManager[]{tm}, new SecureRandom());
        SSLSocketFactory factory = context.getSocketFactory();

        String host = s.getInetAddress().getHostName();
        SSLSocket socket = (SSLSocket) factory.createSocket(s, host, s.getPort(), true);
        socket.setSoTimeout(10000);
        
        X509Certificate certificate = (X509Certificate) ks.getCertificate(host);
        if(certificate!=null && CAX509TrustManager.isValid(certificate))
        {
        	return socket;
        }
	    try {
	            System.out.println("Starting SSL handshake...");
	            socket.startHandshake();
	            System.out.println("No errors, certificate is already trusted");
	            X509Certificate[] chain = tm.chain;
	        if (chain == null || chain.length==0) {
	            System.out.println("Could not obtain server certificate chain");
	            return null;
	        }
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return socket;
    }

    private static class CAX509TrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;
        private KeyStore keyStore;
        private String password;
        
        public  MessageDigest sha1  = null;
        public  MessageDigest md5 = null;
        

        public CAX509TrustManager(X509TrustManager tm, KeyStore ks,String password) throws NoSuchAlgorithmException {
        	this.tm = tm;
        	this.keyStore = ks;
        	sha1 = MessageDigest.getInstance("SHA1");
        	md5 = MessageDigest.getInstance("MD5");
        	this.password = password;
		}

		public X509Certificate[] getAcceptedIssuers() {
        	
            return tm.getAcceptedIssuers();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        	tm.checkClientTrusted(chain, authType);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
        	if(this.chain==null)
      	   {
      		   this.chain = getAcceptedIssuers();
      	   }
        	if(chain!=null)
           {
        	   for (int i = 0; i < chain.length; i++) {
        		   X509Certificate certificate = chain[i];
        		   saveToKeyStore(certificate);
        	   }
           }
        }
        public void saveToKeyStore(X509Certificate certificate) throws CertificateEncodingException
        {
        	try {
        	   X509Certificate cert = certificate;
               System.out.println
                       (" Subject " + cert.getSubjectDN());
               System.out.println("  Issuer  " + cert.getIssuerDN());
               sha1.update(cert.getEncoded());
               System.out.println("  sha1    " + toHexString(sha1.digest()));
               md5.update(cert.getEncoded());
               System.out.println("  md5     " + toHexString(md5.digest()));
               
               String alias = keyStore.getCertificateAlias(cert);
               if(alias==null || alias!=null && !isValid(certificate))
               {
            	   alias = cert.getSubjectDN().getName();
            	   keyStore.setCertificateEntry(alias, certificate);
               	   OutputStream out = new FileOutputStream(KEYSTORE_PATH);
               	   keyStore.store(out, password.toCharArray());
                   out.close();
                   chain = Arrays.copyOf(chain, chain.length+1);
                   chain[chain.length-1] = certificate;
                   System.out.println(certificate);
               }
			
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
        private static boolean isValid(X509Certificate cert)
        {
        	if(cert==null)
        	{
        		return false;
        	}
        	try {
    			cert.checkValidity();
    		} catch (CertificateExpiredException e) {
    			e.printStackTrace();
    			return false;
    		} catch (CertificateNotYetValidException e) {
    			e.printStackTrace();
    		}
    		return true;
        }
    }

}

















