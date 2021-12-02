package com.revature.rphSecurity;


import com.revature.rphSecurity.annotations.EndPointSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {
	@Autowired
	RPHSecurityService rphSecurityService;

	@EndPointSecurity(allowedUserTypes = "Operator")
	@GetMapping
	public String get(@RequestHeader String Authorization){
		return "Hello";
	}
	@GetMapping("/login")
	public String givemekey(){
		Map<String,String> map = new HashMap<>();
		map.put("test","test1");
		return rphSecurityService.generateToken("Operator", map);
	}
}
