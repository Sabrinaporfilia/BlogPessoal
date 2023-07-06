package com.generation.blogpessoal.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.generation.blogpessoal.model.Usuario;

public class UserDetailsImpl implements UserDetails {
	
	private static final long serialVersionUID = 1L;
	
	private String userName;
	private String password;
	
	// O atributo authorities é responsável por receber os Direitos de Acesso do Usuário
	private List<GrantedAuthority> authorities;
	
	public UserDetailsImpl(Usuario user) {
		this.userName =  user.getUsuario();
		this.password = user.getSenha();
	}
	
	public UserDetailsImpl() { }

	
	
	
	//Método getAuthorities(), responsável por retornar os Direitos de Acesso do Usuário (Autorizações ou Roles)
	//Observe que na assinatura do Método getAuthorities(), 
	//nos parâmetros da Collection, foi inserido um sinal de interrogação 
	// Este sinal (?)significa que o Método pode receber um Objeto de qualquer Classe. Se os Direitos de Acesso fossem implementados, a interrogação seria substituída pelo nome da Classe responsável por definir os roles do usuário.
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userName ;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
