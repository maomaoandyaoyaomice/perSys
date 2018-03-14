package org.aptech.shiro.permission.controller;

import java.util.List;

import javax.annotation.Resource;

import org.aptech.shiro.permission.dao.SysPermissionDao;
import org.aptech.shiro.permission.pojo.SysPermission;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/permission")
public class SysPermissionController {
	@Resource
	private SysPermissionDao sysPermissionDao;

	public void setSysPermissionDao(SysPermissionDao sysPermissionDao) {
		this.sysPermissionDao = sysPermissionDao;
	}
	
	@RequestMapping("/index")
	public String index() throws Exception {
		return "syspermission/index";
	}
	@RequestMapping("/list")
	@ResponseBody
	public List<SysPermission> list() throws Exception {
		return sysPermissionDao.getAll();
	}
	
}






