package com.isp.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequestProvider {
    private String username;
    private String password;
    private String email;
    private String state;
    private String city;
    private String pincode;
    private String url;

}
