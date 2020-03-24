package org.believe.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.believe.security.AuthorizationConstants;
import org.believe.toolkit.ClockConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author WangYi
 * @since 2019/6/20
 */
@Component
public class TokenProvider {

	@Autowired
	private ClockConverter clockConverter;

  private static final String AUTHORITIES_KEY = "auth";
	private final SecretKey key = generalKey();

	/**
	 * 生成简单的包含用户名和过期时间的jwt并进行base64加密
	 *
	 * @param userName   用户名
	 * @param expireDate 过期时间
	 * @return
	 */
	public String generationJwt(final String userName, final LocalDate expireDate, final boolean encode) {
		final Map<String, Object> tokenClaimsMap = new HashMap<>();
		Assert.notNull(userName, "username can not be empty");
		Assert.notNull(expireDate, "password can not be empty");
		tokenClaimsMap.put("userName", userName);
		tokenClaimsMap.put("expireDate", expireDate.toString());
		String token = Jwts.builder().addClaims(tokenClaimsMap).setSubject(userName)
				.setHeaderParam("expireDate", expireDate.toString())
				.signWith(SignatureAlgorithm.HS256, key).compact();
		return encode ? Base64Utils.encodeToString(token.getBytes(StandardCharsets.UTF_8)) : token;
	}

  public String createToken(Authentication authentication,Date expiration) {
    String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

    return Jwts.builder()
            .setSubject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(SignatureAlgorithm.HS256, key)
            .setExpiration(expiration)
            .compact();
  }

	/**
	 * 解密jwt
	 *
	 * @param jwtStr
	 * @return
	 * @throws Exception
	 */
	public Claims parseJwt(final String jwtStr) {
		Assert.notNull(jwtStr, "encryptJwt is necessary");
		return Jwts.parser().setSigningKey(key).parseClaimsJws(jwtStr).getBody();
	}

	/**
	 * 获取token header
	 *
	 * @param jwtStr
	 * @return
	 */
	public Header parseJwtHeader(final String jwtStr) {
		return Jwts.parser().setSigningKey(key).parse(jwtStr).getHeader();
	}

	/**
	 * 解密加密的jwt
	 *
	 * @param encryptJwt
	 * @return
	 * @throws Exception
	 */
	public Claims parseEncryptJwt(final String encryptJwt) {
		Assert.notNull(encryptJwt, "encryptJwt is necessary");
		final String jwtByte = new String(
						Base64Utils.decode(encryptJwt.getBytes()), StandardCharsets.UTF_8);
		return parseJwt(jwtByte);
	}

	/**
	 * 由字符串生成加密key
	 *
	 * @return
	 */
	public SecretKey generalKey() {
		String stringKey = AuthorizationConstants.JWT_SECRET;
		byte[] encodedKey = stringKey.getBytes(StandardCharsets.UTF_8);
		return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
	}

	/**
	 * 效验token
	 *
	 * @param token
	 * @return
	 */
	public boolean checkJwt(final String token) {
		Claims tokenStr = this.parseEncryptJwt(token);
		return tokenStr != null;
	}

	/**
	 * 获取username
	 *
	 * @param authToken
	 * @return
	 */
	public String getUsernameFromToken(String authToken) {
		Claims claims = this.parseJwt(authToken);
		return claims.get("userName", String.class);
	}

	public Authentication getAuthentication(String token) {
		Claims claims = this.parseJwt(token);

		Collection<? extends GrantedAuthority> authorities =
						Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
										.map(SimpleGrantedAuthority::new)
										.collect(Collectors.toList());

		User principal = new User(claims.getSubject(), "", authorities);

		return new UsernamePasswordAuthenticationToken(principal, token, authorities);
	}

	/**
	 * 获取过期时间
	 *
	 * @param authToken
	 * @return
	 */
	public LocalDate getExpireDate(String authToken) {
		Claims claims = this.parseJwt(authToken);
		return clockConverter.strToLocalDate(claims.get("expireDate").toString());
	}

	/**
	 * 效验token
	 */
	public boolean validateToken(String authToken) {
		final Claims claims = this.parseJwt(authToken);
		final String userName = claims.get("userName").toString();
		final String subject = claims.getSubject();
		final LocalDate tokenHeaderDate = clockConverter.strToLocalDate(parseJwtHeader(authToken).get("expireDate").toString());
		final LocalDate claimsDate = clockConverter.strToLocalDate(claims.get("expireDate").toString());
		return userName.equals(subject)
				&& tokenHeaderDate.isEqual(claimsDate)
				&& !claimsDate.isBefore(LocalDate.now()) || claimsDate.isEqual(LocalDate.now());
	}
}
