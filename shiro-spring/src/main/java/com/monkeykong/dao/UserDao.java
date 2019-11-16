package com.monkeykong.dao;

import com.monkeykong.vo.User;

import java.util.List;

/**
 * @author czj
 */
public interface UserDao {

    User getUserByUsername(String username);

    List<String> getRolesByUsername(String username);

    List<String> getPermissionsByRole(String role);

}
