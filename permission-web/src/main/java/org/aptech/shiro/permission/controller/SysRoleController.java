package org.aptech.shiro.permission.controller;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.aptech.shiro.permission.dao.SysPermissionDao;
import org.aptech.shiro.permission.dao.SysRoleDao;
import org.aptech.shiro.permission.pojo.SysRole;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/role")
public class SysRoleController {
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
	
	@RequestMapping("/all")
	@ResponseBody
	public List<SysRole> all() throws Exception {
		return sysRoleDao.getAll();
	}

	@RequestMapping("/toAssign")
	public String toAssign(Integer rid,ModelMap modelMap) throws Exception {
		modelMap.put("roleId", rid);
		return "sysrole/assign";
	}
	
	@RequestMapping("/assign")
	@ResponseBody
	public Map<String, Object> assign(Integer roleId,Integer[] ids) throws Exception {
		Map<String, Object> map = new HashMap<>();
		
		sysPermissionDao.deletePermissionsByRoleId(roleId);
		sysPermissionDao.addRolePermissions(roleId, Arrays.asList(ids));
		map.put("result", true);
		return map;
	}
	
	@RequestMapping("/getPermissions")
	@ResponseBody
	public List<Integer> selectPermission(Integer roleId) throws Exception {
		return sysPermissionDao.getPermissionIdsByRoleId(roleId);
	}
	
	@RequestMapping(value="/index",method=RequestMethod.GET)
	public String index() throws Exception {
		return "sysrole/index";
	}
	
	@RequestMapping(value="/form",method=RequestMethod.GET)
	public String form() throws Exception {
		return "sysrole/sysrole_form";
	}
	
	@RequestMapping("/list")
	@ResponseBody
	public Map<String, Object> list(Integer page, Integer rows,@RequestParam(defaultValue="id") String sort,@RequestParam(defaultValue="asc") String order,SysRole condition) throws Exception {
		Map<String, Object> map = new HashMap<>();
		
		int start = (page - 1) * rows;
		List<SysRole> list = sysRoleDao.getListByCondition(start, rows, condition, sort, order);
		int total = sysRoleDao.getCountByCondition(condition);
		
		map.put("rows", list);
		map.put("total", total);
		
		return map;
	}
	
	@RequestMapping(value="/add",method=RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> add(SysRole role,Integer[] roleIds){
		Map<String, Object> map = new HashMap<>();
		sysRoleDao.add(role);
		map.put("result", true);
		return map;
	}
	
	@RequestMapping(value="/edit",method=RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> edit(SysRole user,Integer[] roleIds){
		Map<String, Object> map = new HashMap<>();
		sysRoleDao.update(user);
		map.put("result", true);
		return map;
	}
	
	@RequestMapping("/batchDelete")
	@ResponseBody
	public Map<String, Object> batchDelete(Integer[] ids) throws Exception {
		Map<String, Object> map = new HashMap<>();
		sysRoleDao.deleteByIds(ids);
		map.put("result", true);
		return map;
	}
	@RequestMapping("/view")
	@ResponseBody
	public SysRole view(Integer id) throws Exception {
		return sysRoleDao.getById(id);
	}
	
}






