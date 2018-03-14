package org.apetch.shiro.permission.test;

import org.aptech.shiro.permission.pojo.SysPermission;
import org.aptech.shiro.permission.pojo.SysRole;
import org.permission.utils.ProjectUtils;

public class TestGenerate {
	public static void main(String[] args) throws Exception{
		ProjectUtils.setClasses(new Class[] {SysPermission.class});
		
//		ProjectUtils.generateDaoInterface();
		ProjectUtils.generateMappers();
	}
}
