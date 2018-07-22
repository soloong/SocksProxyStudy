package com.tianwt.rx.socks;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import com.tianwt.rx.http.SSLTrustManager;

public class SocksClient {

	
	public static void main(String[] args) throws Exception {
		
		
	}
	private static void testSocksClient() {
		try {
			Socket socket = new Socket("127.0.0.1", 1080);
			socket.getOutputStream().write(new byte[]{0x05,0x09,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,(byte) 0x80,(byte) 0xff});
			InputStream stream = socket.getInputStream();
			
			byte[] buf = new byte[2];
			
			stream.read(buf, 0, 2);
			System.out.println("Ver:"+buf[0]);
			
			buf[1] = 0x00; //为了测试，这里忽略服务器响应的method
			
			/**
			 * 
			 *http://www.360doc.com/content/13/0927/08/11681374_317366312.shtml
			 * 如果是IPv4地址，这里是big-endian序的4字节数据

            如果是FQDN，比如"www.nsfocus.net"，这里将是:

            0F 77 77 77 2E 6E 73 66 6F 63 75 73 2E 6E 65 74  //ip地址第一位 0F不属于ip，而是表示ip地址的长度

            注意，没有结尾的NUL字符，非ASCIZ串，第一字节是长度域

            如果是IPv6地址，这里是16字节数据。

			 * 
			 */
			byte[] remoteHostBuf = "www.baidu.com".getBytes();
			byte[] remoteHostPort = SocksUtils.intToBytes(80);
			byte[] tempBuf = new byte[]{0x05,0x01,0x00,0x03,(byte) remoteHostBuf.length};
			byte[] sendBuf = new byte[remoteHostBuf.length+tempBuf.length+2];
			System.arraycopy(tempBuf, 0, sendBuf, 0, tempBuf.length);
			System.arraycopy(remoteHostBuf, 0, sendBuf,tempBuf.length, remoteHostBuf.length);
			System.arraycopy(remoteHostPort, 2, sendBuf,tempBuf.length+remoteHostBuf.length, 2);
			
			socket.getOutputStream().write(sendBuf);
			socket.close();
			
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
