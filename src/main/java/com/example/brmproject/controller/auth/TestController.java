package com.example.brmproject.controller.auth;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.brmproject.domain.entities.UserEntity;
import com.example.brmproject.service.imp.UserDetailsServiceImpl;

import jakarta.servlet.http.HttpServletRequest;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
public class TestController {
  @Autowired
  UserDetailsServiceImpl userDetailsServiceImpl;

  @GetMapping("/all")
  public String allAccess() {
    return "Public Content.";
  }

  @GetMapping("/me")
  @PreAuthorize("hasAuthority('CUSTOMER') or hasAuthority('STAFF') or hasAuthority('ADMIN')")
  public UserEntity userAccess(HttpServletRequest req) {
    return userDetailsServiceImpl.whoami(req);
  }

  @GetMapping("/mod")
  @PreAuthorize("hasAuthority('STAFF')")
  public String moderatorAccess() {
    return "Moderator Board.";
  }

  @GetMapping("/admin")
  @PreAuthorize("hasAuthority('ADMIN')")
  public String adminAccess() {
    return "Admin Board.";
  }
    
}
