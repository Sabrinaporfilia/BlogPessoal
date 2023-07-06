package com.generation.blogpessoal.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.repository.UsuarioRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	
	// Implementa o Método loadUserByUsername(String username), 
	//da Interface UserDetailsService, que receberá o usuário através da tela de login do sistema.
	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		
		
		//Cria um Objeto da Classe Optional do tipo Usuario, que receberá o retorno da Query Method 
		// findByUsuario(String usuario),implementada na Interface UsuarioRepository, 
		//para checar se o usuário digitado está persistido no Banco de dados, ou seja, se ele existe.
		Optional<Usuario> usuario = usuarioRepository.findByUsuario(userName);
		
		if(usuario.isPresent())
			return new UserDetailsImpl(usuario.get());
		else  
			throw new ResponseStatusException(HttpStatus.FORBIDDEN);
	}

}
