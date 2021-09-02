package com.isp.repository;

import com.isp.model.Isp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IspRepository extends JpaRepository<Isp,Long> {
    Optional<Isp> findByUsername(String username);
}
