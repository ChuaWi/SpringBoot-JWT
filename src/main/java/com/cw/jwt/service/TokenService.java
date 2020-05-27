package com.cw.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cw.jwt.entity.User;
import org.springframework.stereotype.Service;

/**
 *
 * @date 2020-05-26
 */

@Service("TokenService")
//写一个token的生成方法
public class TokenService {
    public String getToken(User user) {
        String token="";
        // 存入需要保存在token的信息，这里把用户ID存入token
        token= JWT.create().withAudience(user.getId())
                .sign(Algorithm.HMAC256(user.getPassword()));
        // 使用HMAC256生成token,密钥则是用户的密码
        return token;
    }
}
