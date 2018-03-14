package org.aptech.shiro.permission.shiro;

import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.aptech.shiro.permission.dao.SysPermissionDao;
import org.aptech.shiro.permission.dao.SysUserDao;
import org.aptech.shiro.permission.pojo.SysPermission;
import org.aptech.shiro.permission.pojo.SysUser;

public class CustomRealm extends AuthorizingRealm {
	private SysUserDao sysUserDao;
	
	private SysPermissionDao sysPermissionDao;
	
	public void setSysUserDao(SysUserDao sysUserDao) {
		this.sysUserDao = sysUserDao;
	}

	public void setSysPermissionDao(SysPermissionDao sysPermissionDao) {
		this.sysPermissionDao = sysPermissionDao;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("用户授权验证！");
		SysUser user = (SysUser) principals.getPrimaryPrincipal();
		
		List<String> list = sysPermissionDao.getPermissionCodeByUserId(user.getId());
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addStringPermissions(list);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		System.out.println("用户登录认证！");
		String principal = (String) token.getPrincipal();
		SysUser sysUser = sysUserDao.getByUsername(principal);
		
		if (sysUser == null) {
			return null;
		}
		
		//根据用户编号查询用户的功能菜单
		List<SysPermission> menus = sysPermissionDao.getPermissionsByUserId(sysUser.getId(), "menu");
		sysUser.setMenus(menus);
		
		return new SimpleAuthenticationInfo(sysUser,sysUser.getPassword(),ByteSource.Util.bytes(sysUser.getSalt()),this.getName());
	}

}



