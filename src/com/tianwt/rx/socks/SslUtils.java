package com.tianwt.rx.socks;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
 
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
 
public class SslUtils {
 
    private static void trustAllHttpsCertificates() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[1];
        TrustManager tm = new miTM();
        trustAllCerts[0] = tm;
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
 
    static class miTM implements TrustManager,X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
 
        public boolean isServerTrusted(X509Certificate[] certs) {
            return true;
        }
 
        public boolean isClientTrusted(X509Certificate[] certs) {
            return true;
        }
 
        public void checkServerTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }
 
        public void checkClientTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }
    }
     
    /**
     * 忽略HTTPS请求的SSL证书，必须在openConnection之前调用
     * @throws Exception
     */
    public static void ignoreSsl() throws Exception{
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String urlHostName, SSLSession session) {
                System.out.println("Warning: URL Host: " + urlHostName + " vs. " + session.getPeerHost());
                return true;
            }
        };
        trustAllHttpsCertificates();
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }
    
    
    public static void testHttps() throws IOException
    {
    	
    	Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1",443));
		//URL url = new URL("https://imququ.com/post/web-proxy.html");
		URL url = new URL("http://www.oschina.net/");
		HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection(proxy);
		httpURLConnection.setDoOutput(true);
		httpURLConnection.setDoInput(true);
		httpURLConnection.setRequestMethod("GET");
		
		//String data = "name=zhangsan&age=20";
		//httpURLConnection.setRequestProperty("Content-Length", ""+data.getBytes("UTF-8").length);
		//httpURLConnection.getOutputStream().write(data.getBytes("UTF-8"));
		//httpURLConnection.getOutputStream().flush();
		httpURLConnection.connect();
		System.out.println(httpURLConnection.getHeaderFields());
		InputStream inputStream = httpURLConnection.getInputStream();
		
		 byte[] buf = new byte[127];
		 int dataLength = -1;
		 
		 StringBuilder sb = new StringBuilder();
		 
		 while ((dataLength=inputStream.read(buf, 0, buf.length))!=-1)
		 {
			 sb.append(new String(buf, 0, dataLength));
			 
		 } 
		 System.out.println(httpURLConnection.getHeaderFields());
		 System.out.println(sb.toString());
    }
    
    public static void main(String[] args) {
		try {
			testHttps();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}