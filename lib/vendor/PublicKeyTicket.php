<?php

class PublicKeyTicket
{
	protected $pubkey_path;
	protected $privkey_path;
	protected $privkey_passphrase;
	protected $digest_type;
	protected $bauth_key;

	function __construct( $digest_type, $pubkey_path, $privkey_path=null, $privkey_passphrase=null, $bauth_key=null)
	{
		if (!extension_loaded('openssl'))
			throw new Exception('class PublicKeyTicket requires the OpenSSL module to be instanciated.');

		// Check the digest algorithm is supported by the environment
		if( !in_array( $digest_type, openssl_get_md_methods(true) ) )
			throw new Exception("PublicKeyTicket::__construct(): Unsupported digest type '$digest_type'.");


		// Check the BAUTH encryption key length if not null
		if( $bauth_key !== null && strlen($bauth_key) != 16 )
			throw new Exception("PublicKeyTicket::__construct(): Basic auth encryption key must be exactly 16 characters.");

		// Load attributes
		$this->digest_type = $digest_type;
		$this->pubkey_path = $pubkey_path;
		$this->privkey_path = $privkey_path;
		$this->privkey_passphrase = $privkey_passphrase;
		$this->bauth_key = $bauth_key;
	}


	public function authorize( $config, $redirect_handler=null)
	{
		$redirect_function = $redirect_handler ?? 'PublicKeyTicket::redirect_handler';

		$arg_back = $config['TKTAuthBackArgName'] ?? 'back';
		$cookie_name = $config['TKTAuthCookieName'] ?? 'auth_pubtkt';
		$expected_token = $config['TKTAuthToken'];

		$badip_url = $config['TKTAuthBadIPURL'] ?? $config['TKTAuthLoginURL'];
		$multifactor_url = $config['TKTAuthMultifactorURL'] ?? $config['TKTAuthLoginURL'];
		$refresh_url = $config['TKTAuthRefreshURL'] ?? $config['TKTAuthLoginURL'];
		$timeout_url = $config['TKTAuthTimeoutURL'] ?? $config['TKTAuthLoginURL'];
		$timeout_post_url = $config['TKTAuthPostTimeoutURL'] ?? $config['TKTAuthTimeoutURL'] ?? $config['TKTAuthLoginURL'];
		$unauth_url = $config['TKTAuthUnauthURL'] ?? $config['TKTAuthLoginURL'];

		$require_2fa = isset($config['TKTAuthRequireMultifactor']) ?
			(  $config['TKTAuthRequireMultifactor'] == true
			|| $config['TKTAuthRequireMultifactor'] == 1
			|| $config['TKTAuthRequireMultifactor'] == 'on' ) : false;

		$require_ssl = isset($config['TKTAuthRequireSSL']) ? 
			(  $config['TKTAuthRequireSSL'] == true 
			|| $config['TKTAuthRequireSSL'] == 1 
			|| $config['TKTAuthRequireSSL'] == 'on' ) : false;

		// Get session ticket from cookies, if applicable
		if( !isset( $_COOKIE[$cookie_name]) )
			// Redirect to login page (TKTAuthLoginURL)
			call_user_func( $redirect_function, $config['TKTAuthLoginURL']);

		// Enforce TLS connection, if applicable 
		if( $require_ssl && ( !isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on' ) )
			// Redirect to login page (TKTAuthLoginURL)
			call_user_func( $redirect_function, $config['TKTAuthLoginURL']);

		$ticket = $_COOKIE[$cookie_name];

		if( $this->verify( $ticket) !== true )
			// Redirect to login page (TKTAuthLoginURL)
			call_user_func( $redirect_function, $config['TKTAuthLoginURL']);

		// Extract ticket data
		$ticket_attrs = self::parse( $ticket);

		// Fail validation if no expiration date, or if ticket expired
		if( $ticket_attrs['validuntil'] < time() )
		{
			// redirect to timeout page (TKTAuthTimeoutURL / TKTAuthPostTimeoutURL)
			$target = ($_SERVER['REQUEST_METHOD'] == 'POST') ? $timeout_post_url : $timeout_url;
			call_user_func( $redirect_function, $target);
		}

		// check required token
		$ticket_tokens = explode( ',', $ticket_attrs['tokens']);
		if( !empty($expected_token) && !in_array( $expected_token, $ticket_tokens) )
			// Redirect to login page (TKTAuthUnauthURL)
			call_user_func( $redirect_function, $unauth_url);

		// Get remote IP address, preferably from proxy if applicable.
		// It is of the responsibility of the web server to determine the trustability of the X-Forwarded-For header.
		$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
		if( isset($ticket_attrs['cip']) && $ticket_attrs['cip'] != $client_ip )
			// Redirect to login page (TKTAuthBadIPURL)
			call_user_func( $redirect_function, $badip_url);

		if( $require_2fa && $ticket_attrs['multifactor'] != 1 )
			// Redirect to second factor authentication
			call_user_func( $redirect_function, $multifactor_url);

		if( isset($ticket_attrs['graceperiod']) && $ticket_attrs['graceperiod'] < time() )
			// Redirect to transparent ticket renewal (TKTAuthRefreshURL)
			call_user_func( $redirect_function, $refresh_url);

		// Add basic authentication information to environment
		if( isset($ticket_attrs['bauth']) )
		{
			list( $user, $pass) = explode( ':', $ticket_attrs['bauth'], 2);
			
			putenv( "PHP_AUTH_USER=$user" );
			putenv( "PHP_AUTH_PW=$pass" );
			putenv( "AUTH_TYPE=Basic" );
		}

		return $ticket_attrs;
	}

	public function generate( $params)
	{
		// Check if we were given a private key
		if( $this->privkey_path === null )
			throw new Exception('PublicKeyTicket->generate(): No private key supplied.');

		// Attempt to load the private key
		if( $this->privkey_passphrase !== null )
			$h_pvkey = openssl_get_privatekey( $this->privkey_path, $this->privkey_passphrase);
		else
			$h_pvkey = openssl_get_privatekey( $this->privkey_path);

		if( $h_pvkey === false )
			throw new Exception('PublicKeyTicket->generate(): Failed to load private key.');

		// User ID
		$tkt = "uid={$params['uid']};";

		// Client IP (optional)
		if( !empty($params['clientip']) )
			$tkt .= "cip={$params['clientip']};";

		// Ticket validity
		$tkt .= "validuntil={$params['validuntil']};";

		// Ticket grace period
		if( isset($params['graceperiod']) && is_numeric($params['graceperiod']) && $params['graceperiod'] > 0 )
			$tkt .= "graceperiod=".($params['validuntil']-$params['$graceperiod']).";";

		// Tokens (optional) 
		if( !empty($params['tokens']) )
		{
			$tokens = is_array($params['tokens']) ? implode( ',', $params['tokens']) : $params['tokens'];
			$tkt .= "udata=$tokens;";
		}

		// Basic authentication
		if( !empty($params['bauth']) )
		{
			$bauth = $params['bauth'];

			// Inline bauth encryption
			if( isset($params['bauth_key']) )
			{
				// Encrypt with argument-supplied BEK
				if( strlen($params['bauth_key']) != 16 )
					throw new Exception("PublicKeyTicket::generate(): Basic auth encryption key must be exactly 16 characters.");

				$bauth = self::encrypt_bauth( $params['bauth'], $params['bauth_key']);
			} 
			elseif ( $this->bauth_key !== null )    // Key format already checked in self::__construct()
				// Encrypt with the BEK supplied during instanciation, if applicable
				$bauth = self::encrypt_bauth( $params['bauth'], $this->bauth_key);
			else
				// Cleartext
				$bauth = $params['bauth'];

			$tkt .= "bauth=" . base64_encode($bauth) . ";";
		}

		// User data
		if( !empty($params['udata']) )
			$tkt .= "udata={$params['udata']};";

		// MFA flag
		$multifactor = 0;
		if( isset($params['multifactor']) && $params['multifactor'] )
			$multifactor = 1;
		$tkt .= "multifactor=$multifactor";     // Last ';' is appended after the signature

		// Sign ticket
		$result = openssl_sign( $tkt, $sig, $h_pvkey, $this->digest_type);
		openssl_free_key( $h_pvkey);

		if( $result === false )
			throw new Exception('PublicKeyTicket->generate(): openssl_sign() failed.');

		return $tkt . ';sig=' . base64_encode($sig);
	}

	public function verify( $ticket)
	{
		// Load public key
		$h_pkey = openssl_pkey_get_public( $this->pubkey_path);

		if( $h_pkey === false )
			throw new Exception('PublicKeyTicket->verify(): Unable to load public key.');

		// Strip signature
		$sig_pos = strpos( $ticket, ";sig=");

		if( $sig_pos === false )
			return false;

		// Extract the data to verify
		$ticket_data = substr( $ticket, 0, $sig_pos);
		$signature = base64_decode( substr( $ticket, $sig_pos+5));

		// Check signature
		if( openssl_verify( $ticket_data, $signature, $h_pkey) === 1 )
			return true;

		return false;
	}

	public static function encrypt_bauth( $bauth, $key, $nonce=null)
	{
		$cipher  = 'AES-128-CBC';
		$options = OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING;

		if( $nonce === null )
		{
			$nonce = openssl_random_pseudo_bytes( openssl_cipher_iv_length( $cipher), $is_secure);
		
			if( $is_secure !== true )
				throw new Exception('PublicKeyTicket::encrypt_bauth(): Nonce not generated with a CSPRNG. Check configuration.');
		}

		$ciphertext = openssl_encrypt( PublicKeyTicket::pad_zero( $bauth), 'AES-128-CBC', $key, $options, $nonce);
		return $nonce . $ciphertext;
	}

	public static function decrypt_bauth( $bauth, $key)
	{
		$cipher  = 'AES-128-CBC';
		$options = OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING;
		$nonce_len = openssl_cipher_iv_length( $cipher);

		$nonce = substr( $bauth, 0, $nonce_len);
		$ciphertext = substr( $bauth, $nonce_len);

		$cleartext = openssl_decrypt( $ciphertext, 'AES-128-CBC', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $nonce);

		return trim($cleartext);
	}

	public static function pad_zero($data)
	{
		$len = 16;
		if (strlen($data) % $len) {
			$padLength = $len - strlen($data) % $len;
			$data .= str_repeat("\0", $padLength);
		}
		return $data;
	}

	public static function parse( $ticket)
	{
		$result = array();

		// Extract Key/Value strings
		$avps = explode( ';', $ticket);

		// Split Key and Value, and store them in the result array
		foreach( $avps as $avp )
		{
			list( $key, $value) = explode( '=', $avp, 2);
			$result[$key] = $value;	
		}

		return $result;
	}

	public static function redirect_handler( $target_url, $back_url=null, $back_arg_name=null)
	{
		// Back argument name to pass in the redirection URL.
		$_back_aname = $back_arg_name ?? 'back';

		// The URL we wish to come back to. Defaults to current request if not supplied
		$_server = $_SERVER['SERVER_NAME'] . ( $_SERVER['SERVER_PORT'] != 443 ? ":{$_SERVER['SERVER_PORT']}" : '' );
		$_back_url = $back_url ?? ("{$_SERVER['REQUEST_SCHEME']}://$_server{$_SERVER['REQUEST_URI']}" );

		// Select the HTTP redirect code according to the current 
		$redir_code = ($_SERVER['REQUEST_METHOD'] == 'GET') ? 303 : 307;

		// Determine if we're adding the argument to an existing argument list.
		$arg_operator = ( str_contains($target_url, '?') ) ? '&' : '?';

		// Perform the redirection
		http_response_code( $redir_code);
		header( "Location: {$_back_url}{$arg_operator}{$_back_aname}={$_back_url}");

		exit();
	}
}
