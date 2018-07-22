package com.tianwt.rx.socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.util.HashMap;
import java.util.Map;

import javax.net.ServerSocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.tianwt.rx.http.SSLCertInstaller;
import com.tianwt.rx.http.SSLTrustManager;

public class SocksProxyServer {

	private int port  = 1080;
	private int backlog = 25; //最大连接数

	private ServerSocket mSocketServer;
	
	private static final int KEY_VER_NMETHOD_METHODS = 0; 
	private static final int KEY_DST_INFO = 1; 
	
	private static ThreadLocal<Map<Integer,byte[]>> bytesOnThread = new ThreadLocal<Map<Integer,byte[]>>();

	public SocksProxyServer(int backlog)
	{
		this.backlog = backlog;
	}
	
	public SocksProxyServer(int port,int backlog)
	{
		this.port = port;
		this.backlog = backlog;
	}
	
	private ServerSocket createSocketServer() throws IOException
	{
		ServerSocketFactory defaultSocketFactory = ServerSocketFactory.getDefault();
		ServerSocket serverSocket = defaultSocketFactory.createServerSocket(port, backlog);
		return serverSocket;
		
	}
	public void startServer() throws IOException
	{
		startServer(0);
	}
	
	public void startServer(int timeout) throws IOException
	{
		mSocketServer = createSocketServer();
		mSocketServer.setSoTimeout(timeout);
		Socket socketClient = mSocketServer.accept();
		if(socketClient.getSoTimeout()==0)
		{
			socketClient.setSoTimeout(10000);
		}
		socketClient.setTcpNoDelay(true);
		InputStream inputStream = socketClient.getInputStream();
		System.out.println("Start Server Success !");
		byte[] buf = new byte[2];
		int len = inputStream.read(buf,0,2);
		appendToMapOnLocalThread(KEY_VER_NMETHOD_METHODS,buf);
		if(len==2)
		{
			sendToHandler(socketClient, buf);
		}else{
			System.err.println("Error Client,byte length error");
		}
		 inputStream.close();
		 socketClient.close();
	}

	private void sendToHandler(Socket socketClient, byte[] buf) throws IOException {
		try {
			switch (buf[0]) 
			{
			case 0x04:
				{
					System.out.println("Socks4 Proxy Protocol！");
					handleSocks4(buf,socketClient);
				}
				break;
				case 0x05:
				{
					System.out.println("Socks5 Proxy Protocol！");
					handleSocks5(buf,socketClient);
				}
				break;
				default:
					System.err.println("Error Client");
					break;
			}
		} catch (IOException e) {
			e.printStackTrace();
			socketClient.close();
			throw e;
		}
	}
	
	private void handleSocks4(byte[] buf,Socket socketClient)
	{
		
	}
	
	private void handleSocks5(byte[] buf,Socket socketClient) throws IOException
	{
		 InputStream inputStream = socketClient.getInputStream();
		 OutputStream outputStream = socketClient.getOutputStream();
		 String dstHostName = null;
		 int dstHostPort = 0;
		 
		 int len = buf[1];
		 buf = new byte[len];
		 len = inputStream.read(buf,0,len);
		 
		 appendToMapOnLocalThread(KEY_VER_NMETHOD_METHODS,buf);
		 printLog(buf);
		 
		 /**
		 int rndIndex = Math.min((int)(Math.random()*10),len); //随机选一种方法
		 sendBytes[1] = buf[rndIndex];
		 **/
		 byte[] sendBytes = new byte[]{0x05,0x00}; // VER=0x05,METHOD=0x00
		 outputStream.write(sendBytes);
		 
		 //客户端响应
		 buf = new byte[4];
		 len = inputStream.read(buf);
		 appendToMapOnLocalThread(KEY_DST_INFO, buf);
		 if(len==4)
		 {
			 if(buf[3]==0x01) //ipv4
			 {
				 System.out.println("byte=2,type=ipv4,bigendient");
				 buf = new byte[4];
				 len = inputStream.read(buf);
				 if(len==4)
				 {
					 appendToMapOnLocalThread(KEY_DST_INFO, buf);
					 String bytesToIp = SocksUtils.bytesToIp(buf);
					 dstHostName =  bytesToIp;
				 }
				
			 }else if(buf[3]==0x03){ //域名地址
				 
				 System.out.println("byte=first_byte,type=domain");
				 buf = new byte[1];
				 len = inputStream.read(buf);
				 appendToMapOnLocalThread(KEY_DST_INFO, buf);
				 
				 int domainLength = buf[0]>0?buf[0]:buf[0]*(-1)+127;	
				 buf = new byte[domainLength];
				 len = inputStream.read(buf);
				 
				 if(len==domainLength)
				 {
					 appendToMapOnLocalThread(KEY_DST_INFO, buf);
					 String domain = new String(buf, 0,len);
					 dstHostName = domain;
					 System.out.println(domain);
				 }
				 
			 }else if(buf[3]==0x04) {//ipv6
				
				 System.out.println("byte=16,type=ipv6");
				 buf = new byte[16];
				 len = inputStream.read(buf);
				 if(len==16)
				 {
					 appendToMapOnLocalThread(KEY_DST_INFO, buf);
					 String bytesToIp = SocksUtils.bytesToIp(buf);
					 dstHostName = bytesToIp;
					 System.out.println(bytesToIp);
				 }
			 }else{
				 System.err.println("Error byte Length");
				 return;
			 }
			 buf = new byte[4]; //ip地址属于大端，存储在高位
			 len = inputStream.read(buf,2,2);
			 if(len==2)
			 {
				 dstHostPort =  SocksUtils.bytesToInt(buf); //
				 appendToMapOnLocalThread(KEY_DST_INFO, buf);
				 estimateProxyStatus(socketClient, dstHostName, dstHostPort);
			 }else{
				 System.err.println("Error byte Length");
			 }

		 }else{
			 System.err.println("Error byte Length");
			 
		 }
	}

	private void estimateProxyStatus(Socket socketClient, String dstHostName, int dstHostPort) throws IOException
			 {
		 byte[] dstInfo = getFromMapOnLocalThread(KEY_DST_INFO);
		 int connectType = dstInfo[1];
		 
		 switch (connectType) {
		
		 case 0x01:
			 
			 Socket remoteHost = estimateConnectRemoteHost(socketClient,dstHostName,dstHostPort);
			 if(remoteHost!=null)
			 {
				 doProxyService(socketClient, remoteHost);
			 }
			break;
		case 0x02:
			estimateBindRemoteHost(socketClient,dstHostName,dstHostPort);
			break;
		case 0x03:
			estimateUDPAssociateRemoteHost(socketClient,dstHostName,dstHostPort);
		break;

		default:
			break;
		}
	}

	private void doProxyService(Socket socketClient, Socket remoteHost) throws IOException {
		    
		    try {
		    	if(remoteHost.getPort()!=80 && remoteHost.getPort()!=8080)
		    	{
			    	SSLSocket  tempSocket = SSLTrustManager.getTlsTrustAllSocket(remoteHost,true);
			    	tempSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
						
						@Override
						public void handshakeCompleted(HandshakeCompletedEvent event) {
							 	System.out.println(" Handshake finished!");
		                        System.out.println(" CipherSuite:" + event.getCipherSuite());
		                        System.out.println(" SessionId " + event.getSession());
		                        System.out.println(" PeerHost " + event.getSession().getPeerHost());
						}
					});
			    	tempSocket.startHandshake();
			    	SSLSocket sslSocketClient = SSLTrustManager.getTlsTrustAllSocket(socketClient,false);
			    	socketClient = sslSocketClient;
			    	remoteHost = tempSocket;
		    	}
			} catch (Exception e) {
				e.printStackTrace();
			}
		
			 System.out.println("连接成功！");
			 
			 byte[] proxyBuf = new byte[10*1024*1024];
			 int proxyDataLength = -1;
			 proxyDataLength=socketClient.getInputStream().read(proxyBuf, 0, proxyBuf.length);
			 
			 String clientStr = new String(proxyBuf, 0, proxyDataLength);
			 System.out.println(clientStr);
			 remoteHost.getOutputStream().write(proxyBuf,0,proxyDataLength);
			 
			 InputStream remoteInput = remoteHost.getInputStream();

			 proxyBuf = new byte[1024];
			 int readLength = -1;
			 
			 while((readLength=remoteInput.read(proxyBuf, 0, proxyBuf.length))!=-1)
			{	 
				System.out.println(new String(proxyBuf, 0, readLength));
			    socketClient.getOutputStream().write(proxyBuf, 0, readLength);
		    }
			 socketClient.getOutputStream().flush();
	}



	private Socket estimateConnectRemoteHost(Socket socketClient, String dstHostName, int dstHostPort) {
		
		Socket socket = null;
		byte[] sendBuf = new byte[]{0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
		try {
			  System.out.println("host="+dstHostName+",port="+dstHostPort);
			  socket = new Socket(dstHostName,dstHostPort);
			  socket.setSoTimeout(10000);
			  socket.setTcpNoDelay(true);
			  socket.setKeepAlive(true);
			  socket.setReuseAddress(true);
			  if(null==socket.getRemoteSocketAddress())
			  {
				  socket.close();
				  socket = null;
				  sendBuf[1] = 0x04;
			  }else{
				  byte[] portToBytes = SocksUtils.intToBytes(socket.getLocalPort());
				  sendBuf[sendBuf.length-2] = portToBytes[2];
				  sendBuf[sendBuf.length-1] = portToBytes[3];
			  }
		} catch (UnknownHostException e) {
			e.printStackTrace();
			sendBuf[1] = 0x03;
		} catch (SocketException e) {
			e.printStackTrace();
			sendBuf[1] = 0x05;
		} catch (IOException e) {
			e.printStackTrace();
			sendBuf[1] = 0x06;
		}finally{
			try {
				socketClient.getOutputStream().write(sendBuf, 0, sendBuf.length); //客户端发送评测结果
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return socket;
	}

	private void estimateBindRemoteHost(Socket socketClient, String dstHostName, int dstHostPort) {
		
	}

	private void estimateUDPAssociateRemoteHost(Socket socketClient, String dstHostName, int dstHostPort) {
		
	}
	private void printLog(byte[] buf)
	{
		for (int i = 0; i < buf.length; i++)
		 {
			int method = buf[i];
			 if(method<0)
			{
				 method = 127+Math.abs(method); // byte转int
			}
			System.out.println(method);
		}
	}

	private void appendToMapOnLocalThread(int pos,byte[] buf) {
		Map<Integer, byte[]> map = bytesOnThread.get();
		if(map==null)
		{
			map = new HashMap<Integer,byte[]>();
		}
		byte[] bs = map.get(pos);
		if(bs==null)
		{
			bs = buf;
		}else{
			byte[] tempBuf = bs;
			bs = new byte[tempBuf.length+buf.length];
			System.arraycopy(tempBuf, 0, bs, 0, tempBuf.length);
			System.arraycopy(buf, 0, bs,tempBuf.length, buf.length);
		}
		map.put(pos, bs);
		bytesOnThread.set(map);
	}
	
	private byte[] getFromMapOnLocalThread(int pos)
	{
		Map<Integer, byte[]> map = bytesOnThread.get();
		if(map!=null)
		{
			return map.get(pos);
		}
		return null;
	}
	
	public static void main(String[] args) {
		try {
			new SocksProxyServer(5).startServer();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
