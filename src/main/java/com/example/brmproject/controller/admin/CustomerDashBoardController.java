package com.example.brmproject.controller.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import com.example.brmproject.domain.dto.CustomerDTO;
import com.example.brmproject.service.CustomerService;
import org.springframework.ui.Model;
import org.springframework.http.HttpHeaders;



import java.util.List;

@Controller
public class CustomerDashBoardController {

    @Autowired
    CustomerService customerService;

    
    @GetMapping("/staff/customers/getAll")
    public String allCustomer(Model model, @RequestHeader HttpHeaders headers) {
        List<CustomerDTO> allCustomer = customerService.findAll();
        
        // In ra các header
        model.addAttribute("allCustomer", allCustomer);
        return "adminTemplate/CustomerDashBoard";
    }

}
