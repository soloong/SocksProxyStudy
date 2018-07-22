package com.tianwt.rx.socks;

import java.net.InetAddress;

public class SocksUtils {

	 /**  
		 * 将int数值转换为占四个字节的byte数组，本方法适用于(高位在前，低位在后)的顺序。  和bytesToInt2（）配套使用 
		 */    
		public static byte[] intToBytes(int value)   
		{   
		    byte[] src = new byte[4];  
		    src[0] = (byte) ((value>>24) & 0xFF);  
		    src[1] = (byte) ((value>>16)& 0xFF);  
		    src[2] = (byte) ((value>>8)&0xFF);    
		    src[3] = (byte) (value & 0xFF);       
		    return src;  
		} 
		
		  /**
	     * 把IP地址转化为int
	     * @param ipAddr
	     * @return int
	     */
	    public static byte[] ipToBytesByReg(String ipAddr) {
	        byte[] ret = new byte[4];
	        try {
	            String[] ipArr = ipAddr.split("\\.");
	            ret[0] = (byte) (Integer.parseInt(ipArr[0]) & 0xFF);
	            ret[1] = (byte) (Integer.parseInt(ipArr[1]) & 0xFF);
	            ret[2] = (byte) (Integer.parseInt(ipArr[2]) & 0xFF);
	            ret[3] = (byte) (Integer.parseInt(ipArr[3]) & 0xFF);
	            return ret;
	        } catch (Exception e) {
	            throw new IllegalArgumentException(ipAddr + " is invalid IP");
	        }

	    }

	    /**
	     * 字节数组转化为IP
	     * @param bytes
	     * @return int
	     */
	    public static String bytesToIp(byte[] bytes) {
	        return new StringBuffer().append(bytes[0] & 0xFF).append('.').append(
	                bytes[1] & 0xFF).append('.').append(bytes[2] & 0xFF)
	                .append('.').append(bytes[3] & 0xFF).toString();
	    }

	    /**
	     * 根据位运算把 byte[] -> int
	     * @param bytes
	     * @return int
	     */
	    public static int bytesToInt(byte[] bytes) {
	        int addr = bytes[3] & 0xFF;
	        addr |= ((bytes[2] << 8) & 0xFF00);
	        addr |= ((bytes[1] << 16) & 0xFF0000);
	        addr |= ((bytes[0] << 24) & 0xFF000000);
	        return addr;
	    }

	    /**
	     * 把IP地址转化为int
	     * @param ipAddr
	     * @return int
	     */
	    public static int ipToInt(String ipAddr) {
	        try {
	            return bytesToInt(ipToBytesByInet(ipAddr));
	        } catch (Exception e) {
	            throw new IllegalArgumentException(ipAddr + " is invalid IP");
	        }
	    }
	    /**
	     * 把IP地址转化为字节数组
	     * @param ipAddr
	     * @return byte[]
	     */
	    public static byte[] ipToBytesByInet(String ipAddr) {
	        try {
	            return InetAddress.getByName(ipAddr).getAddress();
	        } catch (Exception e) {
	            throw new IllegalArgumentException(ipAddr + " is invalid IP");
	        }
	    }

	    /**
	     * 把int->ip地址
	     * @param ipInt
	     * @return String
	     */
	    public static String intToIp(int ipInt) {
	        return new StringBuilder().append(((ipInt >> 24) & 0xff)).append('.')
	                .append((ipInt >> 16) & 0xff).append('.').append(
	                        (ipInt >> 8) & 0xff).append('.').append((ipInt & 0xff))
	                .toString();
	    }
}
