package vn.iotstar.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class RegisterUserModel {
    private String email;

    private String password;

    private String fullName;

    // Tuy chon: duong dan anh dai dien (mac dinh /images/default.svg)
    private String images;
}
