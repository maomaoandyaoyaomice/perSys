package org.apetch.shiro.permission.test;

import org.apache.shiro.crypto.hash.Md5Hash;

public class TestMD5 {
	public static void main(String[] args) {
		Md5Hash md5Hash = new Md5Hash("123456", "qwert");
		String result = md5Hash.toString();
		System.out.println(result);
	}
}
