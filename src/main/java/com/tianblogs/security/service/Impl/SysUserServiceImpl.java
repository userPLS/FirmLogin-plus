package com.tianblogs.security.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.tianblogs.security.entity.SysUser;
import com.tianblogs.security.mapper.SysUserMapper;
import com.tianblogs.security.service.SysUserService;
import com.tianblogs.security.utils.JwtUtils;
import com.tianblogs.security.utils.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUser> implements SysUserService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RedisUtil redisUtil;

    @Override
    public SysUser getByUsername(String username) {
        return this.getOne(new LambdaQueryWrapper<SysUser>().eq(SysUser::getName, username));
    }

    @Override
    public String getUserAuthorityInfo(Long userId) {
        SysUser sysUser = getById(userId);
        return sysUser.getAuthority();
    }

    @Override
    public SysUser getByAccount(String account) {
        return this.getOne(new LambdaQueryWrapper<SysUser>().eq(SysUser::getAccount, account));
    }

    @Override
    public SysUser login(SysUser sysUser) {
        Authentication authentication = null;
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(sysUser.getAccount(), sysUser.getPassword());
        // 将登录接口输入的用户密码创建成临时 authentication 记录到 安全上下文管理器
        // 安全上下文管理器 默认"线程本地模式"："MODE_THREADLOCAL"
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
        authentication = authenticationManager.authenticate(authenticationToken);
        // 清理掉记录
        SecurityContextHolder.clearContext();
        if (Objects.isNull(authentication)){
            throw new RuntimeException("登录失败");
        }
        SysUser user = (SysUser) authentication.getPrincipal();
        String token = jwtUtils.generateToken(user.getAccount());
        redisUtil.set(token, user);
        return user;
    }


}
