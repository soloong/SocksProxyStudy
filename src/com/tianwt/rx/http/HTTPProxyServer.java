package com.tianwt.rx.http;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HTTPProxyServer implements Runnable{

	private int port  = 1080;
	private int backlog = 25; //最大连接数

	private ServerSocket mSocketServer;
	private final static String STATUS_LINE = "Status-Line";
	private static final String PROXY_PREFIX = "proxy-";
	private static final Logger log = Logger.getLogger("HTTPProxyServer");

	public HTTPProxyServer(int backlog)
	{
		log.setLevel(Level.ALL);
		this.backlog = backlog;
	}
	
	public HTTPProxyServer(int port,int backlog)
	{
		this.port = port;
		this.backlog = backlog;
	}
	
	private ServerSocket createSocketServer() throws IOException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException
	{
	   ServerSocket serverSocket =  ServerSocketFactory.getDefault().createServerSocket();
	   serverSocket.setSoTimeout(3000);
	   serverSocket.bind(new InetSocketAddress(port),backlog);
	   return serverSocket;
	}
	@Override
	public void run() {
		Socket socketClient = null;
		try {
			mSocketServer = createSocketServer();
			mSocketServer.setSoTimeout(0);
			 socketClient = mSocketServer.accept();
			if(socketClient.getSoTimeout()==0)
			{
				socketClient.setSoTimeout(10000);
			}
			socketClient.setTcpNoDelay(true);
			InputStream inputStream = socketClient.getInputStream();
			Map<String, Object> parseProxyHeader = parseHeader(inputStream);
			log.fine(parseProxyHeader.toString());
			String statusLine = (String) parseProxyHeader.get(STATUS_LINE);
			String[] status = statusLine.trim().split(" ");
			if(!"CONNECT".equalsIgnoreCase(status[0]))
			{
				proxyHttpScoket(mSocketServer,socketClient,parseProxyHeader);
			}else if(status[0]!=null){
				
				proxySSLSSocket(mSocketServer,socketClient, parseProxyHeader);
			}
			
		} catch (SocketException e) {
			e.printStackTrace();
			try {
				sendErrorStatus(socketClient);
			} catch (Exception e1) {
			} 
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			if(!socketClient.isClosed())
			{
				try {
					socketClient.close();
				} catch (IOException e) {
				}
			}
			socketClient = null;
		}
		
	}
	
	private void proxySSLSSocket(ServerSocket mSocketServer, Socket socketClient, Map<String, Object> proxyHeader)
			throws Exception {
		Socket proxySocket = null;
		   try {
			   
		   String statusLine = (String) proxyHeader.get(STATUS_LINE);
		   String[] status = statusLine.trim().split(" ");
		   URI uri = URI.create("https://"+status[1]);
		   URL url = uri.toURL();
	      
		   proxySocket = SSLCertInstaller.createTrustCASocket(url.getHost(), url.getPort());
		   proxySocket.setSoTimeout(5000);
		   proxySocket.setTcpNoDelay(true);
		   
		   sendFitHeaderToClient(socketClient,null);
		   SSLSocket clientSSLSocket = SSLTrustManager.createTlsConnect2(socketClient);
		
		   Map<String, Object> clientRequestHeader = parseHeader(clientSSLSocket.getInputStream());
		   String mapToString = formatMapToString(clientRequestHeader);
		   OutputStream output = proxySocket.getOutputStream();
		   System.out.println(mapToString);
		   output.write(mapToString.getBytes("utf-8"));
		   output.flush();
		   
		   
		   InputStream input = proxySocket.getInputStream();  
		   int len = -1;
		   byte[] buf = new byte[256];
			while((len=input.read(buf, 0, buf.length))!=-1)
			{
				
				 System.out.println(new String(buf, 0, len));
				 clientSSLSocket.getOutputStream().write(buf,0,len);
				   if(len<buf.length)
				   {
					  // break;
				   }
			}
			clientSSLSocket.getOutputStream().flush();
			
		} catch (Exception e) {
			e.printStackTrace();
		}finally{
			socketClient.getOutputStream().flush();
			proxySocket.close();
		}
	}

	private String formatMapToString(Map<String, Object> clientRequestHeader) {
		
		if(clientRequestHeader==null || clientRequestHeader.size()==0)
		{
			return "";
		}
		String requestLine = (String) clientRequestHeader.remove(STATUS_LINE)+"\r\n";
		clientRequestHeader.put("Upgrade-Insecure-Requests", "1");
		clientRequestHeader.put("Content-Security-Policy", "Upgrade-Insecure-Requests");
		clientRequestHeader.put("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36");
		for (Entry<String, Object> entry : clientRequestHeader.entrySet()) 
		{
			requestLine += entry.getKey()+":"+entry.getValue()+"\r\n";
		}
		requestLine += "\r\n";
		return requestLine;
	}


	
	private void proxyHttpScoket(ServerSocket mSocketServer, Socket socketClient, Map<String, Object> parseProxyHeader) throws IOException   
	{
		String statusLine = (String) parseProxyHeader.remove(STATUS_LINE);
		if(statusLine==null)
		{
			return;
		}
		String[] status = statusLine.trim().split(" ");
		byte[] parseData = parseData(socketClient, status);
		log.fine(new String(parseData, 0, parseData.length));
		HttpURLConnection conn = null;
		try {
			URL url = new URL(status[1]);
			conn =  (HttpURLConnection) url.openConnection();
			conn.setConnectTimeout(10000);
			conn.setRequestMethod(status[0]);
			conn.setInstanceFollowRedirects(true);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			
			for (Entry<String, Object> entry : parseProxyHeader.entrySet())
			{
				if(entry.getKey().toLowerCase().startsWith(PROXY_PREFIX))
				{
					conn.setRequestProperty(entry.getKey().substring(PROXY_PREFIX.length()), ((String) entry.getValue()).trim());
				}
				else{
					conn.setRequestProperty(entry.getKey(), ((String) entry.getValue()).trim());
				}
			}
			String proxyServerHost = mSocketServer.getInetAddress().getHostAddress();
			conn.setRequestProperty("Via", "Proxy-"+proxyServerHost);
			String realIp = socketClient.getInetAddress().getHostAddress();
			conn.setRequestProperty("X-Real-IP",realIp);
			
			log.fine(conn.getRequestProperties().toString());
			
			if(parseData!=null && parseData.length>0)
			{
				conn.getOutputStream().write(parseData);
			}
			InputStream inputStream = conn.getInputStream();
			sendHeaderToClient(socketClient, conn);
			int len = -1;
			byte[] buf = new byte[1024];
			while ((len=inputStream.read(buf, 0, buf.length))!=-1) {
				socketClient.getOutputStream().write(buf, 0, len);
			}
			socketClient.close();
			inputStream.close();
			
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}finally{
			if(conn!=null)
			{
				conn.disconnect();
			}
		}
	}

	private void sendHeaderToClient(Socket socketClient, HttpURLConnection conn)
			throws IOException, UnsupportedEncodingException {
		if(socketClient==null || conn==null || !socketClient.isConnected())
		{
			return;
		}
		Map<String, List<String>> headerFields = conn.getHeaderFields();
		 String respLines = "HTTP/1.1 "+conn.getResponseCode()+" "+conn.getResponseMessage()+"\r\n";
		 for (Entry<String, List<String>> respEntry : headerFields.entrySet()) 
		 {
			 if(respEntry.getKey()!=null&&respEntry.getValue()!=null)
			 {
				 String value = getValueStr(respEntry.getValue());
				 if(respEntry.getKey().trim().equalsIgnoreCase("Transfer-Encoding") && "chunked".equalsIgnoreCase(value))
				 {
					  respLines += "Content-Length:"+conn.getContentLengthLong()+"\r\n";
				 }else{
					 respLines += respEntry.getKey()+":"+getValueStr(respEntry.getValue())+"\r\n";
				 }
			 }
		 }
		respLines+="\r\n";
		socketClient.getOutputStream().write(respLines.getBytes("UTF-8"));
	}

	private String getValueStr(List<String> value) {
		
		if(value==null)
		{
			return "";
		}
		String line = "";
		for (String strLine : value) {
			line += strLine+",";
		}
		if(line.length()>0)
		{
			return line.substring(0,line.length()-1);
		}
		return line;
	}

	private byte[] parseData(Socket socketClient, String[] status)  
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			List<String> asList = Arrays.asList("POST","DELETE","PUT");
			for (int i = 0; i < asList.size(); i++) {
				if(asList.get(i).equalsIgnoreCase(status[0]))
				{
					InputStream stream = socketClient.getInputStream();
					int len = -1;
					byte[] buf = new byte[1024];
					while ((len=stream.read(buf, 0, buf.length))!=-1){
						baos.write(buf, 0, len);
						if(buf.length>len)
						{
							break;
						}
					}
					break;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			log.severe(e.getLocalizedMessage());
		}
		return baos.toByteArray();
	}

	private void sendFitHeaderToClient(Socket socketClient,String msg) throws IOException, UnsupportedEncodingException {
		
		if(socketClient==null || !socketClient.isConnected())
		 {
			   return;
		}
		String gmtTime = getGMTFormatDateTime();
		
		StringBuilder sb = new StringBuilder();
		if(msg!=null)
		{
		    sb.append(msg+"\r\n");
		}else{
			sb.append("HTTP/1.1 200 Connection established\r\n");
		}
		sb.append("Server: HTTPProxyServer/1.0.8.14\r\n");
		sb.append("Date: "+gmtTime+"\r\n");
		sb.append("Proxy-Connection: keep-alive\r\n");
		sb.append("Proxy-agent: HTTPProxyServer 1.1.0\r\n");
		sb.append("Content-Length: 0\r\n\r\n");
		socketClient.getOutputStream().write(sb.toString().getBytes("UTF-8"));
	}
   private void sendErrorStatus(Socket socketClient) throws IOException, UnsupportedEncodingException {
		
	   if(socketClient==null || !socketClient.isConnected())
	   {
		   return;
	   }
		String gmtTime = getGMTFormatDateTime();
		
		StringBuilder sb = new StringBuilder("500 Internal Server Error\r\n");
		sb.append("Server: HTTPProxyServer/1.0.8.14\r\n");
		sb.append("Date: "+gmtTime+"\r\n");
		sb.append("Proxy-Connection: keep-alive\r\n");
		sb.append("Proxy-agent: HTTPProxyServer 1.1.0\r\n");
		sb.append("Content-Length: 0\r\n\r\n");
		socketClient.getOutputStream().write(sb.toString().getBytes("UTF-8"));
	}

	private String getGMTFormatDateTime()
	{
		Date d=new Date();
		SimpleDateFormat format= (SimpleDateFormat) SimpleDateFormat.getDateInstance(0, Locale.ENGLISH);
		format.applyPattern("EEE, dd MMM yyyy HH:mm:ss z");
		format.setTimeZone(TimeZone.getTimeZone("GMT"));
		String gmtTime = format.format(d);
		return gmtTime;
	}
	
	
	public static void main(String[] args) {
		
		new HTTPProxyServer(25).run();
	}
	
	public  Map<String, Object> parseHeader(InputStream is)  
	{
		Map<String, Object> map = new HashMap<String, Object>();
		
		 int len = -1;
		 byte[] buf = new byte[1];
		 ByteArrayOutputStream baos = new ByteArrayOutputStream();
		 baos.write(0x3A);
		 AtomicInteger aIndex = new AtomicInteger(0);
		 try {
			while((len=is.read(buf, 0, buf.length))!=-1)
			 {
				 baos.write(buf, 0, len);
				 if(0x0A==buf[0] || 0x0D==buf[0])
				 {
					 if(aIndex.incrementAndGet()>=4)
					 {
						 break;
					 }
				 }else{
					 aIndex.set(0);
				 }
				
			 }
			
		} catch (IOException e) {
			e.printStackTrace();
		}finally{
			 byte[] array = baos.toByteArray();
			 String headerStr = new String(array, 0, array.length);
			 System.out.println(headerStr);
			 String[] splits = headerStr.split("\r\n");
			 
			 for (String itemHeaderStr : splits) 
			 {
				 if(itemHeaderStr.startsWith(":"))
				 {
					 map.put(STATUS_LINE,itemHeaderStr.substring(1));
					 continue;
				 }
				 String[] kvSplits = itemHeaderStr.split(":");
				 if(kvSplits==null) continue;
				
				 if(kvSplits.length==2){
					map.put(kvSplits[0], kvSplits[1]);
				}else if(kvSplits.length>2){
					String values = kvSplits[1];
					for (int i = 2; i < kvSplits.length; i++) 
					{
						values += ":"+kvSplits[i];
					}
					map.put( kvSplits[0],values);
					
				}
			 }
		}
		 
		 return map;
	}
}
