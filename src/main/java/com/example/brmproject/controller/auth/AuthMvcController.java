package com.example.brmproject.controller.auth;



import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.brmproject.domain.dto.JwtResponseDTO;
import com.example.brmproject.domain.dto.LoginRequestDTO;
import com.example.brmproject.domain.dto.MessageResponseDTO;
import com.example.brmproject.domain.dto.SignupRequestDTO;
import com.example.brmproject.domain.entities.CustomerEntity;
import com.example.brmproject.domain.entities.ERole;
import com.example.brmproject.domain.entities.RoleEntity;
import com.example.brmproject.domain.entities.StaffEntity;
import com.example.brmproject.domain.entities.UserEntity;
import com.example.brmproject.repositories.CustomerEntityRepository;
import com.example.brmproject.repositories.RoleEntityRepository;
import com.example.brmproject.repositories.StaffEntityRepository;
import com.example.brmproject.repositories.UserEntityRepository;
import com.example.brmproject.security.jwt.JwtUtils;
import com.example.brmproject.service.imp.UserDetailsImpl;

import groovyjarjarantlr4.v4.codegen.model.ModelElement;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.security.core.AuthenticationException;




@Controller
public class AuthMvcController {

  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserEntityRepository userEntityRepository;

  @Autowired
  RoleEntityRepository roleEntityRepository;

  @Autowired
  CustomerEntityRepository customerEntityRepository;

  @Autowired
  StaffEntityRepository staffEntityRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  private HttpServletResponse response;

  @GetMapping("/register")
  public String register (Model model){
    SignupRequestDTO signupRequest = new SignupRequestDTO();
    model.addAttribute("signupRequest", signupRequest);

    return "customerTemplate/register";
  }

  @GetMapping("/login")
  public String login (Model model){
    LoginRequestDTO loginRequest = new LoginRequestDTO();
    model.addAttribute("loginRequest",loginRequest);
    return "customerTemplate/login";
  }

  @PostMapping("/login")
    public String login(@Valid @ModelAttribute LoginRequestDTO loginRequest,  BindingResult bindingResult, Model model){
        try {

          if (bindingResult.hasErrors()) {  
            return "customerTemplate/login";
          }

          Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
  
          SecurityContextHolder.getContext().setAuthentication(authentication);
          UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
          String jwt = jwtUtils.generateJwtToken(authentication);
  
          List<String> roles = userDetails.getAuthorities().stream()
          .map(item -> item.getAuthority())
          .collect(Collectors.toList());
          int userId;
          if (roles.stream().anyMatch(role -> role.equalsIgnoreCase("STAFF") || role.equalsIgnoreCase("ADMIN"))) {
            StaffEntity staff = staffEntityRepository.findByUserId(userDetails.getId()).get();
            userId = staff.getId();
            
          } else {
              CustomerEntity customer = customerEntityRepository.findByUserId(userDetails.getId()).get();
              userId = customer.getId();
          }
  
          Cookie cookieJwt = createCookie("jwtToken", jwt);
          Cookie cookieInfo = createCookie("userId", Integer.toString(userId));

          response.addCookie(cookieJwt);
          response.addCookie(cookieInfo);
  
            return "redirect:/register";
      } catch (AuthenticationException e) {       
          model.addAttribute("loginRequest", loginRequest);        
          model.addAttribute("errorAuthen", "Wrong username or password");
          return "customerTemplate/login";
      }
  }


  @PostMapping("/register")
  public String registerCustomer(@Valid @ModelAttribute SignupRequestDTO signUpRequest, BindingResult bindingResult, Model model) {
    // if (userEntityRepository.existsByUsername(signUpRequest.getUsername())) {

    //       model.addAttribute("errors", "Email is already exist!");
    //       return "customerTemplate/register";
    // }

    // Create new user's account
    UserEntity user = new UserEntity(signUpRequest.getUsername(),
        encoder.encode(signUpRequest.getPassword()));

    Set<RoleEntity> roles = new HashSet<>();
    
    RoleEntity userRole = roleEntityRepository.findByName(ERole.CUSTOMER)
        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
    roles.add(userRole);

    user.setRoles(roles);
    userEntityRepository.save(user);
   
    
    int userId = userEntityRepository.save(user).getId();

    CustomerEntity newCustomer = new CustomerEntity();
    newCustomer.setAddress(signUpRequest.getAddress());
    newCustomer.setEmail(signUpRequest.getUsername());
    newCustomer.setName(signUpRequest.getName());
    newCustomer.setPhone(signUpRequest.getPhone());
    newCustomer.setUserId(userId);
    newCustomer.setUserByUserId(user);
    customerEntityRepository.save(newCustomer);
   
    return "redirect:/login";
  }


  @PreAuthorize("hasAuthority('ADMIN')")
  @PostMapping("/staff/createStaff")
  public String registerStaff(@Valid @ModelAttribute SignupRequestDTO signUpRequest, BindingResult bindingResult, Model model) {
    // if (userEntityRepository.existsByUsername(signUpRequest.getUsername())) {

    //       model.addAttribute("errors", "Email is already exist!");
    //       return "customerTemplate/register";
    // }

    // Create new user's account
    UserEntity user = new UserEntity(signUpRequest.getUsername(),
        encoder.encode(signUpRequest.getPassword()));

    Set<RoleEntity> roles = new HashSet<>();
    
    RoleEntity userRole = roleEntityRepository.findByName(ERole.STAFF)
        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
    roles.add(userRole);

    user.setRoles(roles);
    userEntityRepository.save(user);
    
    int userId = userEntityRepository.save(user).getId();

    StaffEntity newStaff = new StaffEntity();
   
    newStaff.setEmail(signUpRequest.getUsername());
    newStaff.setName(signUpRequest.getName());
    newStaff.setEmployeeCode(RandomStringUtils.randomAlphanumeric(6));
    newStaff.setUserId(userId);
    newStaff.setUserByUserId(user);
    staffEntityRepository.save(newStaff);
   
    return "redirect:/login";
  }



  private Cookie createCookie(String name, String value) {
    Cookie cookie = new Cookie(name, value);
    cookie.setMaxAge(86400000);
    cookie.setPath("/");
    return cookie;
}

  
 
    
}
