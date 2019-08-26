package cn.ruoshy.security.mapper;


import cn.ruoshy.security.entity.Role;
import cn.ruoshy.security.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface UserMapper {

    @Select("SELECT * FROM user where username = #{username}")
    User loadUserByUsername(String username);

    @Select("SELECT * FROM role r,user_role ur where r.id = ur.role_id and ur.user_id = #{id}")
    List<Role> getRoleByUId(Integer id);
}
