package org.believe.security;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.believe.security.auth.AuthPrimary;
import org.believe.security.auth.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author WangYi
 * @version 1.0
 * @since 2019/2/19
 */
@Service
public class SecurityUserDetailServiceImpl implements UserDetailsService {

  @Autowired
  private AuthRepository authRepository;

  private List<String> roles;

  @Override
  public UserDetails loadUserByUsername(String username) {
    final AuthPrimary authPrimary = authRepository.selectOne(
            new QueryWrapper<AuthPrimary>()
                    .eq("username",username));
    if (authPrimary == null) {
      throw new UsernameNotFoundException("No user found with username " + username);
    }
    this.roles = new ArrayList<>();
    this.roles.add(authPrimary.getRole());
    return create(authPrimary);
  }

  private SecurityUserDetails create(AuthPrimary user) {
    return SecurityUserDetails.builder().id(user.getId()).username(user.getUserName())
            .password(user.getPassword()).authorities(mapToGrantedAuthorities(roles)).build();
  }

  private List<GrantedAuthority> mapToGrantedAuthorities(List<String> authorities) {
    return authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
  }
}
