package com.example.brmproject.controller.customer;

import com.example.brmproject.domain.dto.CustomerDTO;
import com.example.brmproject.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Controller
public class CustomerController {
    private final CustomerService service;
    @Autowired
    public CustomerController(CustomerService service) {
        this.service = service;
    }



    @GetMapping("/customers/new")
    public String registMember(Model model)
    {
        model.addAttribute("customer",new CustomerDTO());

        return "testForm";
    }
    @GetMapping("/employee")
    public String test(Model model)
    {
//        model.addAttribute("customer",new CustomerDTO());

        return "adminTemplate/employees/create";
    }
    @GetMapping("/employee/test")
    public String testsa(Model model)
    {
//        model.addAttribute("customer",new CustomerDTO());

        return "adminTemplate/adminLayout";
    }
    @GetMapping("/employee/test1")
    public String testsadscs(Model model)
    {
//        model.addAttribute("customer",new CustomerDTO());

        return "adminTemplate/employees/index";
    }

    @PostMapping("/customers/new")
    public String create(@ModelAttribute CustomerDTO customerDTO)
    {

        service.createCustomer(customerDTO);
        return "redirect:/customers";
    }
    @GetMapping("/customers")
    public String showAll(Model model)
    {
    //    List<CustomerDTO> list=service.findAll();
    //    model.addAttribute("customers",list);
        return "adminTemplate/test";
    }
}
