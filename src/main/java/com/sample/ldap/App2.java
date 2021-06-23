package com.sample.ldap;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class App2 {

	public static void main(String[] args) {
		SpringApplication.run(App2.class, args);
	}

	
	public boolean authenticate(String user, String pass , DirContext ctx) throws NamingException {
		 

		  String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"; // Unsafe
		  //
		  // If the special value "*)(uid=*))(|(uid=*" is passed as user, authentication is bypassed
		  // Indeed, if it is passed as a user, the filter becomes:
		  // (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
		  // as uid=* match all users, it is equivalent to:
		  // (|(uid=*)(userPassword=...))
		  // again, as uid=* match all users, the filter becomes useless

		  NamingEnumeration<SearchResult> results = ctx.search("ou=system", filter, new SearchControls()); // Noncompliant
		  return results.hasMore();
		}
}
