package com.tianblogs.security.service.Impl;

import com.tianblogs.security.entity.SysUser;
import com.tianblogs.security.service.SysUserService;
import com.tianblogs.security.user.AccountUser;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 *  定义了UserDetails接口的实现类，我们就需要定义UserDetailsService接口的实现类，重写其loadUserByUsername方法，该方法需使用用户名在数据库中查找用户信息返回，返回值需封装成UserDetails。直接上代码：
 *
 *  实现了上述几个接口，从数据库中验证用户名、密码的过程将由框架帮我们完成，是封装隐藏了，所以不懂Spring Security的人可能会对登录过程有点懵，不知道是怎么判定用户名密码是否正确的。
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private SysUserService sysUserService;

    @Override
    public UserDetails loadUserByUsername(String account) throws UsernameNotFoundException {

        SysUser sysUser = sysUserService.getByAccount(account);
        if (sysUser == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        String md5 = DigestUtils.md5Hex("123456");
        boolean matches = BCrypt.checkpw(md5,sysUser.getPassword());
        if(matches) {
            return new AccountUser(sysUser.getId(), sysUser.getName(), sysUser.getPassword(), getUserAuthority(sysUser.getId()));
        }
        else{
            throw new UsernameNotFoundException("用户名或密码错误");
        }


       /*
        Object credentials = SecurityContextHolder.getContext().getAuthentication().getCredentials();
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        final String passHash = encoder.encode((CharSequence)credentials);
        final boolean matches = encoder.matches((CharSequence)credentials, passHash);
        if(matches) {
            return new AccountUser(sysUser.getId(), sysUser.getName(), sysUser.getPassword(), getUserAuthority(sysUser.getId()));
        }
        else{
            throw new UsernameNotFoundException("用户名或密码错误");
        }

        System.out.println(md5);
        String hashpw = BCrypt.hashpw(md5,BCrypt.gensalt());
        System.out.println(hashpw);
        System.out.println(BCrypt.checkpw(md5,"$2a$10$r/NBI5XJrwhRyui6MnL9h.PsqDZ4aUBi/YSUyVN2BM/ShsTneQjHy"));
//        System.out.println(matchesPassword(md5,"$2a$10$YLAzJYgEkhyg7eCTV52uHu1rg4Yeyl6Sv67gqo/6zgjrG9t7.k44q"));
        return new AccountUser(sysUser.getId(), sysUser.getName(), sysUser.getPassword(), getUserAuthority(sysUser.getId()));*/

    }

    /**
     * 获取用户权限信息（角色、菜单权限）
     * @param userId
     * @return
     */
    public List<GrantedAuthority> getUserAuthority(Long userId) {
    	// 实际怎么写以数据表结构为准，这里只是写个例子
        // 角色(比如ROLE_admin)，菜单操作权限(比如sys:user:list)
        String authority = sysUserService.getUserAuthorityInfo(userId);     // 比如ROLE_admin,ROLE_normal,sys:user:list,...

        return AuthorityUtils.commaSeparatedStringToAuthorityList(authority);
    }
}
