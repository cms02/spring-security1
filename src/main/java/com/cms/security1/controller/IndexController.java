package com.cms.security1.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cms.security1.config.auth.PrincipalDetails;
import com.cms.security1.model.User;
import com.cms.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IndexController {
	
//	@Autowired
//	private UserRepository userRepository;
	
	private final UserRepository userRepository;
	
	private final BCryptPasswordEncoder bCryptPasswordEncoder ;
	
	@GetMapping("/test/login")
	public @ResponseBody String testLogin(
			Authentication authentication, 
			@AuthenticationPrincipal PrincipalDetails userDetails) { //DI(의존성주입)
		System.out.println("/test/login ================");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication: " + principalDetails.getUser());
		
		System.out.println("userDetails : " + userDetails.getUser());
		return "세션 정보 확인하기";
	}
	
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(
			Authentication authentication/* , @AuthenticationPrincipal PrincipalDetails userDetails */
			, @AuthenticationPrincipal OAuth2User oauth) { //DI(의존성주입)
		System.out.println("/test/login ================");
//		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication: " + oauth2User.getAttributes());
		System.out.println("oauth2User: " + oauth.getAttributes());
		
//		System.out.println("userDetails : " + userDetails.getUser());
		return "OAuth 세션 정보 확인하기";
	}
	//localhost:8787/
	//localhost:8787
	@GetMapping({"/",""})
	public String index() {
		// mustache 기본폴더 src/main/resources/
		// 뷰리졸버 설정 : templates (prefix), .mustache (suffix) 생략가능
		return "index";	// src/main/resources/templates/index.mustache
	}
	
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails: " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	//스프링시큐리티가 해당주소를 낚아채버림 - SecurityConfig 파일 생성 수 작동안함.
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		String rawPsssword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPsssword);
		user.setPassword(encPassword);
		userRepository.save(user);	//회원가입 잘되지만 비밀번호 1234 => 시큐리티로 로그인을 할 수 없음. 이유는 패스워드가 암호화가 안되어있음
		return "redirect:/loginForm";
	}
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}
	

}
