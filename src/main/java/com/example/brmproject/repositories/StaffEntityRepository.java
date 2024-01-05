package com.example.brmproject.repositories;

import com.example.brmproject.domain.entities.StaffEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface StaffEntityRepository extends JpaRepository<StaffEntity, Integer> {

    Optional<StaffEntity> findByUserId(int userId);
}