package com.example.brmproject;

import java.util.Set;
import java.util.HashSet;

import org.apache.commons.lang3.RandomStringUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.brmproject.domain.entities.ERole;
import com.example.brmproject.domain.entities.RoleEntity;
import com.example.brmproject.domain.entities.StaffEntity;
import com.example.brmproject.domain.entities.UserEntity;
import com.example.brmproject.repositories.RoleEntityRepository;
import com.example.brmproject.repositories.StaffEntityRepository;
import com.example.brmproject.repositories.UserEntityRepository;

@SpringBootApplication
public class BrmprojectApplication implements CommandLineRunner{
//confi modelMapper
    @Bean
    public ModelMapper modelMapper(){

        return new ModelMapper();

    }

    @Autowired
	RoleEntityRepository roleRepository;

	@Autowired
	StaffEntityRepository staffRepository;

	@Autowired
	UserEntityRepository userRepository;

	@Autowired
	PasswordEncoder encoder;

    //config passwork encoder.



    //
    public static void main(String[] args) {
        SpringApplication.run(BrmprojectApplication.class, args);
    }

    @Override
		public void run(String... params) throws Exception {
			if(!roleRepository.findByName(ERole.CUSTOMER).isPresent()) {
				roleRepository.save(new RoleEntity(ERole.CUSTOMER));
			}

			if(!roleRepository.findByName(ERole.STAFF).isPresent()) {
				roleRepository.save(new RoleEntity(ERole.STAFF));
			}

			if(!roleRepository.findByName(ERole.ADMIN).isPresent()) {
				roleRepository.save(new RoleEntity(ERole.ADMIN));
			}	



			if(!userRepository.existsByUsername("admin@gmail.com")) {
				UserEntity admin = new UserEntity("admin@gmail.com", encoder.encode("123123123"));
				Set<RoleEntity> roles = new HashSet<>();
				RoleEntity userRole = roleRepository.findByName(ERole.ADMIN).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
				roles.add(userRole);
				admin.setRoles(roles);
				userRepository.save(admin);
				
				StaffEntity staffEntity = new StaffEntity();
				staffEntity.setEmail(admin.getUsername());
				staffEntity.setName("admin");
				staffEntity.setEmployeeCode(RandomStringUtils.randomAlphanumeric(6));
				staffEntity.setUserId(admin.getId());
				staffEntity.setUserByUserId(admin);
				staffRepository.save(staffEntity);
			}

	



		}

}
