package org.aptech.shiro.permission.dao;

import java.util.List;

import org.apache.ibatis.annotations.Param;
import org.aptech.shiro.permission.pojo.SysPermission;

public interface SysPermissionDao extends CommonDao<SysPermission, Integer>{

	public List<Integer> getPermissionIdsByRoleId(Integer roleId);
	
	public void deletePermissionsByRoleId(Integer roleId);
	
	public void addRolePermissions(@Param("roleId") Integer roleId,@Param("perIds") List<Integer> perIds);
	/**
	 * 根据登录用户的编号查询对应的权限信息
	 * @param userId
	 * @param type
	 * @return
	 */
	public List<SysPermission> getPermissionsByUserId(@Param("userId") Integer userId,@Param("type") String type);
	
	public List<String> getPermissionCodeByUserId(Integer userId);
}








