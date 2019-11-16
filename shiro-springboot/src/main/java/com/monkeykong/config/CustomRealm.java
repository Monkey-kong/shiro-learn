package com.monkeykong.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author monkeykong
 */
public class CustomRealm extends AuthorizingRealm {

    Map<String,String> userPwdMap = new HashMap<>();
    {
        userPwdMap.put("admin","0192023a7bbd73250516f069df18b500");
        userPwdMap.put("alvin", "5939aff55aae6d5f9a5120ec233058d3");
    }

    /**
     * 设置权限和角色
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) SecurityUtils.getSubject().getPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> permissionSet = new HashSet<>();
        permissionSet.add("user:show");
        permissionSet.add("user:admin");
        info.setStringPermissions(permissionSet);
        Set<String> rolesSet = new HashSet<>();
        rolesSet.add("admin");
        info.setRoles(rolesSet);
        return info;
    }

    /**
     * 设置用户密码信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = (String) authenticationToken.getPrincipal();
        // String userPwd = new String((char[]) authenticationToken.getCredentials());
        //根据用户名从数据库获取密码
        String password = findPasswordByUserName(username);
        if (username == null) {
            throw new AccountException("用户名为空");
        }
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username, password,getName());
        simpleAuthenticationInfo.setCredentialsSalt(ByteSource.Util.bytes(username));
        return simpleAuthenticationInfo;
    }

    private String findPasswordByUserName(String userName)
    {
        return userPwdMap.get(userName);
    }

    public static void main(String[] args) {
        Md5Hash md5Hash = new Md5Hash("Pass9876","alvin");
        System.out.println(md5Hash.toString());
    }
}
