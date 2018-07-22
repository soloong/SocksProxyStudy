package com.tianwt.rx.http.test;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import com.tianwt.rx.http.SSLTrustManager;

public class HttpClientTest {

	public static void main(String[] args) throws Exception {
		
		Socket socket = new Socket(InetAddress.getByName("www.baidu.com"), 80);
		socket.setTcpNoDelay(true);
		socket.setSoTimeout(3000);
		socket.setReuseAddress(true);
		
		StringBuilder sb = new StringBuilder();
		sb.append("GET /s?wd=123456 HTTP/1.1\r\n");
		sb.append("Host: www.baidu.com\r\n");
		sb.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n");
		sb.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36\r\n");
		sb.append("Connection:keep-alive\r\n");
		sb.append("Accept-Language:zh-CN,zh;q=0.8\r\n");
		sb.append("\r\n");
		
		OutputStream out = socket.getOutputStream();
		out.write(sb.toString().getBytes("UTF-8"));
		InputStream is = socket.getInputStream();
		byte[] ibyte = read(is);
		System.out.println(new String(ibyte, 0, ibyte.length));
		
		out.write(sb.toString().getBytes("UTF-8"));
		ibyte = read(is);
		System.err.println(new String(ibyte, 0, ibyte.length));
		
	}
	
	public static byte[] read(InputStream is)
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int available = 0;
		byte[] buf = null;
		try {
			available = is.available();
		} catch (IOException e) {
			e.printStackTrace();
		}finally{
			if(available>0)
			{
				buf = new byte[available];
			}else{
				buf = new byte[1024];
			}
		}
		try {
			int len = 0;
			while ((len=is.read(buf, 0, buf.length))!=-1){
				baos.write(buf, 0, len);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return baos.toByteArray();
	}

	private static void testsocks() {
		try {
			Proxy proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1",1080));
			HttpURLConnection httpURLConnection = (HttpURLConnection) (new URL("http://www.baidu.com/s?wd=12345")).openConnection(proxy);
			//HttpURLConnection httpURLConnection = SSLTrustManager.connectTrustAllServer("https://www.baidu.com/s?wd=12345", proxy);
			httpURLConnection.setDoOutput(true);
			httpURLConnection.setDoInput(true);
			httpURLConnection.setRequestMethod("GET");
			//String data = "name=zhangsan&age=20";
			//httpURLConnection.setRequestProperty("Content-Length", ""+data.getBytes("UTF-8").length);
			httpURLConnection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36");
			
			httpURLConnection.connect();
			//httpURLConnection.getOutputStream().write(data.getBytes("UTF-8"));
			//httpURLConnection.getOutputStream().flush();
		
			InputStream inputStream = httpURLConnection.getInputStream();
			
			 byte[] buf = new byte[1024*1024];
			 int dataLength = -1;
			 
			 StringBuilder sb = new StringBuilder();
			 
			 System.out.println(httpURLConnection.getHeaderFields());
			 while ((dataLength=inputStream.read(buf, 0, buf.length))!=-1)
			 {
				 System.out.println(new String(buf, 0, dataLength));
				 
			 } 
			
		}  catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (ProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void trustCA() {
		
		try {
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1",1080));
			HttpURLConnection httpURLConnection = SSLTrustManager.connectProxyTrustCA("https://imququ.com/post/web-proxy-2.html", proxy);
			httpURLConnection.setDoOutput(true);
			httpURLConnection.setDoInput(true);
			//String data = "name=zhangsan&age=20";
			//httpURLConnection.setRequestProperty("Content-Length", ""+data.getBytes("UTF-8").length);
			//httpURLConnection.getOutputStream().write(data.getBytes("UTF-8"));
			//httpURLConnection.getOutputStream().flush();
			httpURLConnection.setRequestMethod("GET");
			httpURLConnection.connect();
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
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (ProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void trustAllServer() {
		Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress("127.0.0.1",1088));
		try {
			HttpURLConnection conn = SSLTrustManager.connectTrustAllServer("https://imququ.com/post/web-proxy-2.html",proxy);
			conn.connect();
			
			Map<String, List<String>> headerFields = conn.getHeaderFields();
			
			InputStream inputStream = conn.getInputStream();
			 byte[] buf = new byte[127];
			 int dataLength = -1;
			 System.out.println(headerFields);
			 while ((dataLength=inputStream.read(buf, 0, buf.length))!=-1)
			 {
				 System.out.println(new String(buf, 0, dataLength));
				 
			 } 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
