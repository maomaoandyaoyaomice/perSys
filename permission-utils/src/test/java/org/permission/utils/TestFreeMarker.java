package org.permission.utils;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import freemarker.template.Configuration;
import freemarker.template.Template;

public class TestFreeMarker {

	@Test
	public void test() throws Exception {
		//1. 准备模型数据 
		Map<String, Object> model = new HashMap<>();
		model.put("name", "Jackson");
		
		//用map来模拟实体类
		Map<String, Object> computer = new HashMap<>();
		computer.put("brand", "Lenovo");
		computer.put("price", 5300);
		computer.put("color", "Silver");
		model.put("computer", computer);
		
		List<String> fruits = Arrays.asList("apple","orange","banana","watermellon");
//		List<String> fruits = new ArrayList<>();
		model.put("fruits", fruits);
		
		
		//2. 读取模板文件
		Configuration configuration = new Configuration(Configuration.VERSION_2_3_23);
		configuration.setDirectoryForTemplateLoading(new File("src/test/resources"));
		configuration.setDefaultEncoding("utf-8");
		
		Template template = configuration.getTemplate("demo.ftl");
		//3. 使用Freemarker合成
//		Writer out = new OutputStreamWriter(System.out); //输出到控制台
		Writer out = new OutputStreamWriter(new FileOutputStream(new File("/Users/yaoyaomice/Desktop/free.html")));
		template.process(model, out);
		
		System.out.println("generate success!");
	}

}






