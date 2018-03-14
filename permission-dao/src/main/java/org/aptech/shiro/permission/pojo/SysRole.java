package org.aptech.shiro.permission.pojo;

import java.io.Serializable;

import javax.annotation.Resource;

public class SysRole implements Serializable {
	@Resource
	private Integer id;
	
	private String name;
	
	private Integer available;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Integer getAvailable() {
		return available;
	}

	public void setAvailable(Integer available) {
		this.available = available;
	}
	
}
