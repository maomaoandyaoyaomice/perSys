<!DOCTYPE html>
<html lang="zh">
<head>
	<meta charset="UTF-8">
	<title>Document</title>
</head>
<body>
	Hello,${name}. <br/>
	<h1>Computer info</h1>
	Brand : ${computer.brand} <br/>
	Price : ${computer.price} <br/>
	Color : ${computer.color}
	<hr/>
	
	<#if computer.price &gt;= 5300 >
		小贵
	<#else>
		太便宜了吧！
	</#if>
	<hr/>
	
	<h1>the following are my favorite fruits</h1>
	<ul>
		<#list fruits as f>
			<li>${f}</li>
		<#else>
		I have no hobbies!
		</#list>
	</ul>
	<hr/>
	<#list fruits as item>
		${item} <#if item_has_next>,</#if>
	</#list>
</body>
</html>






