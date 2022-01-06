package com.cms.security1.config.oauth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cms.security1.config.auth.PrincipalDetails;
import com.cms.security1.model.User;
import com.cms.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

//구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{
	
	private final BCryptPasswordEncoder bBCryptPasswordEncoder;
	
	private final UserRepository userRepository;
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration: " + userRequest.getClientRegistration());//registrationId로 어떤 OAuth로 로그인했는지 확인가능
		System.out.println("getAccessToken: " + userRequest.getAccessToken().getTokenValue());
		
		OAuth2User oAuth2User = super.loadUser(userRequest);
		//구글로그인 버튼 클릭 -> 구글로그인참 -> 로그인완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken 요청
		//userRequest 정보 -> loadUser 함수 -> 구글로부터 회원프로필을 받아준다.
		System.out.println("getAttributes: " + oAuth2User.getAttributes());
		
		String provider 	= userRequest.getClientRegistration().getClientId(); //google
		String providerId	= oAuth2User.getAttribute("sub");
		String username		= provider + "_" + providerId;	//google_109125453223412
		String password 	= bBCryptPasswordEncoder.encode("겟인데어");
		String email		= oAuth2User.getAttribute("email");
		String role			= "ROLE_USER";
		
		User userEntity 	= userRepository.findByUsername(username);
		
		if(userEntity == null) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}
		
		//회원가입을 강제로 진행해볼 예정
		return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
	}

}
