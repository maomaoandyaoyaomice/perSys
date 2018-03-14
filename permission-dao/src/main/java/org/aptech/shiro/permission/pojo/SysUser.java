package org.aptech.shiro.permission.pojo;

import java.io.Serializable;
import java.util.List;

import javax.annotation.Resource;

public class SysUser implements Serializable {
	@Resource
	private Integer id;
	
	private String username;
	
	private String password;
	
	private String salt;
	
	private Integer locked;
	
	private List<SysRole> sysRoles; //用户拥有的角色集合
	
	private List<SysPermission> menus ;

	public List<SysPermission> getMenus() {
		return menus;
	}

	public void setMenus(List<SysPermission> menus) {
		this.menus = menus;
	}

	public List<SysRole> getSysRoles() {
		return sysRoles;
	}

	public void setSysRoles(List<SysRole> sysRoles) {
		this.sysRoles = sysRoles;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public Integer getLocked() {
		return locked;
	}

	public void setLocked(Integer locked) {
		this.locked = locked;
	}
	
}
