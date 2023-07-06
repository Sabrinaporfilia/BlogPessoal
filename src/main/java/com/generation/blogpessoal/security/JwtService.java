package com.generation.blogpessoal.security;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

// A Classe foi anotada com a anotação @Component, o que indica que esta Classe é uma Classe de Componente. 
//Classe de Componente é uma Classe gerenciada pelo Spring, que permite Injetar e Instanciar 
//qualquer Dependência especificada na implementação da Classe, em qualquer outra Classe, sempre que necessário.
@Component
public class JwtService {
	
	// Este atributo armazenará a Chave de assinatura do Token JWT (secret). 
	//Este Atributo foi definido com o modificador final, porque este valor será constante, 
	
	// static, porque o atributo deve estar associado apenas e exclusivamente a esta Classe,
	//ou seja, é uma variável de Classe e não do Objeto.
	public static final String SECRET = "32fc39a3b6bf39e10cfd3db37c72dbc2be11ff4b8f6918c698382b25e23a2162";
	
	
	//Key getSignKey() é responsável por codificar a SECRET em Base 64 e gerar a 
	// Assinatura (Signature) do Token JWT,codificada pelo Algoritmo HMAC SHA256.
	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes); 
	}
	
	//O Método extractAllClaims(String token) retorna todas as claims, inseridas no Payload do Token JWT.
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSignKey()).build()
				.parseClaimsJws(token).getBody();
		}
	
	
	//O Método extractClaim(String token, Function< Claims, T > claimsResolver) 
	//retorna uma claim específica, inserida no Payload do Token JWT.
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	//O Método extractExpiration(String token) recupera os dados da Claim exp, onde se encontra a data e o horário
	//de expiração do Token JWT,através do Método extractClaim(String token, Function< Claims, T > claimsResolver).
	
	//A Interface Funcional Function recebeu como entrada a Classe Claims e na saída, receberá a execução do 
	//Método getSubject(),que está sendo chamado através do operador de referência de métodos (::),
	//que retorna o valor da claim sub.
	public String extractUsername(String token) {
		return extractClaim(token, Claims ::getSubject);
	}
	/*O Método extractExpiration(String token) recupera os dados da Claim exp, onde se encontra a data e 
	 o horário de expiração do Token JWT, através do Método extractClaim(String token, Function< Claims,
	  T > claimsResolver).

	A Interface Funcional Function recebeu como entrada a Classe Claims e na saída, receberá a execução 
	do Método getExpiration(), que está sendo chamado através do operador de referência de métodos (::), q
	ue retorna o valor da claim exp. */
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims ::getExpiration);
	}
	
	/*O Método isTokenExpired(String token) recupera os dados da Claim exp, onde se encontra a data e o horário
	 de expiração do Token JWT, através do Método extractExpiration(String token) e verifica através 
	 do Método before(), da Classe Date, se o token está ou não expirado (fora da data e hora de validade).
	 Se a data e a hora do token for anterior a data e hora atual, o Token JWT estará expirado, 
	 o Método retornará true e será necessário autenticar novamente para gerar um novo Token JWT válido.*/
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	
	/* O Método validateToken(String token, UserDetails userDetails) valida se o Token JWT pertence ao usuário 
	 * que enviou o token através do Cabeçalho de uma requisição HTTP, na propriedade Authorization. O Método 
	 * recebe 2 parâmetros: O Token JWT (token) e o Objeto da Classe UserDetailsImpl 
	 * (implementação da Interface UserDetails), contendo as credenciais, autorizações e propriedades
	 *  do usuário autenticado. */
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return(username.equals(userDetails.getUsername()) && !isTokenExpired(token));
		
	}
	//O Método createToken(Map<String, Object> claims, String userName) cria o Token JWT.
	private String createToken(Map<String, Object> claims, String userName) {
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(userName)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}
	
	//O Método generateToken(String userName) é responsável por gerar um novo Token a partir do usuario (e-mail)
	/*Linha 66: Cria uma Collection Map, chamada claims, para enviar as claims personalizadas. Como não enviaremos 
	 * nenhuma claim personalizada em nosso Token JWT, ela permanecerá vazia e será enviada como parâmetro do Método createToken. */
	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName);
	}
	
}
