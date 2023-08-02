package org.zerock.ex2.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Getter
@Setter
@ToString
public class MemberDTO extends User implements OAuth2User {

    private String email;
    private String pw;

    private String nickname;

    private boolean social;

    private List<String> roleNames = new ArrayList<>();



    public MemberDTO(String email, String pw, String nickname, boolean social, List<String> roleNames){

        super(email,pw, roleNames.stream().map(str -> new SimpleGrantedAuthority(str)).collect(Collectors.toList()));

        this.email = email;
        this.pw = pw;
        this.roleNames = roleNames;
        this.nickname = nickname;
        this.social = social;

    }

    public Map<String, Object> getClaims() {

        return Map.of(
                "email", email,
                "pw", pw,
                "nickname", nickname,
                "social", social,
                "roleNames", roleNames);


    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public String getName() {
        return this.email;
    }
}
