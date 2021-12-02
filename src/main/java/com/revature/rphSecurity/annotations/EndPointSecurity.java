package com.revature.rphSecurity.annotations;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface EndPointSecurity {
	String[] allowedUserTypes();
}
