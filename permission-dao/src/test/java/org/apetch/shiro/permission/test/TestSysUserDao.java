package org.apetch.shiro.permission.test;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.aptech.shiro.permission.dao.SysPermissionDao;
import org.aptech.shiro.permission.dao.SysRoleDao;
import org.aptech.shiro.permission.dao.SysUserDao;
import org.aptech.shiro.permission.pojo.SysPermission;
import org.aptech.shiro.permission.pojo.SysRole;
import org.aptech.shiro.permission.pojo.SysUser;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("classpath:applicationContext-mybatis.xml")
public class TestSysUserDao {
	@Resource
	private SysUserDao sysUserDao;
	@Resource
	private SysRoleDao sysRoleDao;
	@Resource
	private SysPermissionDao sysPermissionDao;
	
	public void setSysPermissionDao(SysPermissionDao sysPermissionDao) {
		this.sysPermissionDao = sysPermissionDao;
	}

	public void setSysRoleDao(SysRoleDao sysRoleDao) {
		this.sysRoleDao = sysRoleDao;
	}

	public void setSysUserDao(SysUserDao sysUserDao) {
		this.sysUserDao = sysUserDao;
	}
	@Test
	public void testGetAllPers() {
		List<SysPermission> list = sysPermissionDao.getAll();
		for (SysPermission parent : list) {
			System.out.println(parent.getText());
			for (SysPermission child : parent.getChildren()) {
				System.out.println("\t" + child.getText());
			}
		}
	}
	
	@Test
	public void testGetbyId() {
		SysRole role = sysRoleDao.getById(1);
		System.out.println(role.getName());
	}

	@Test
	public void testGetByCondition() {
		
		SysUser condition = new SysUser();
		
		List<SysRole> sysRoles = new ArrayList<>();
		SysRole sysRole = new SysRole();
		sysRole.setId(1);
		sysRoles.add(sysRole);
		
		condition.setSysRoles(sysRoles);
		
		List<SysUser> list = sysUserDao.getListByCondition(0, 5, condition, "id", "asc");
		for (SysUser sysUser : list) {
			System.out.println(sysUser.getUsername());
		}
	}
	
//	@Test
//	public void testAdd() {
//		Md5Hash md5Hash = new Md5Hash("123456", "admin");
//		String pwd = md5Hash.toString();
//		for (int i = 0; i < 15; i++) {
//			SysUser sysUser = new SysUser();
//			sysUser.setUsername("user-"+i);
//			sysUser.setPassword(pwd);
//			sysUser.setSalt("admin");
//			sysUser.setLocked(0);
//			
//			sysUserDao.add(sysUser);
//		}
//	}

}





