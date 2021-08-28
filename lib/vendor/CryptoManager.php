<?php

class CryptoManager {
	public static function generateKeyPair( $key_type=OPENSSL_KEYTYPE_RSA, $key_parm=null, $key_pass=null)
	{
		$options = array();
		$options['private_key_type'] = $key_type;

		if( $key_type == OPENSSL_KEYTYPE_EC )
		{
			$options['curve_name'] = $key_parm ?? 'prime256v1';
		}
		else
		{
			$options['private_key_bits'] = $key_parm ?? 3072;
		}

		$key = openssl_pkey_new( $options);
		openssl_pkey_export( $key, $result);
		openssl_pkey_free( $key);
		return $result;
	}

	public static function getPublicFromPrivate( $key, $password=null)
	{
		if( $password === null )
			$pk = openssl_pkey_get_private( $key);
		else
			$pk = openssl_pkey_get_private( $key, $password);

		$result = openssl_pkey_get_details( $pk)['key'];
		openssl_pkey_free( $pk);

		return $result;

	}

	public static function generateCSR( $key, $password, $subject ,$san=null, $ca_level=false, $exts=null)
	{

		// Process subject
		$vals = explode('/', $subject);
		$dn = array();
		
		foreach( $vals as $avp )
		{
			if( empty($avp) )
				continue;
			list( $attr, $val) = explode( '=', $avp, 2);
			$dn[$attr] = $val;
		}
		
		// Prepare OpenSSL config
		$openssl_cnf = "[ req ]\ndistinguished_name = req_dn\nreq_extensions = v3_req\n\n[ req_dn ]\n\n[ v3_req ]\n";
		
		// Add basic constraints
		if( $ca_level !== false )
		{
			if( $ca_level < 0 )
				$openssl_cnf .= "basicConstraints = critical,CA:TRUE\n";
			else
				$openssl_cnf .= "basicConstraints = critical,CA:TRUE,pathlen:${ca_level}\n";
		}
		else
			$openssl_cnf .= "basicConstraints = critical,CA:FALSE\n";

		// Append subjectAltName if applicable
		if( !empty($san) )
			$openssl_cnf .= "subjectAltName = ${san}";

		// Add custom extensions
		if( !empty($exts) )
		{
			if( is_array($exts) )
				foreach( $exts as $line )
					$openssl_cnf .= "${line}\n";
			else
				$openssl_cnf .= "${exts}\n";
		}

		// Write the conf in a temp file
		$conf_fname = tempnam( sys_get_temp_dir(), 'openssl_cnf');
		file_put_contents( $conf_fname, $openssl_cnf);

		echo("<pre>$openssl_cnf</pre>");

		// Setup the openssl options
		$options = array( 
			'digest_alg' => 'sha256',
			'req_extensions' => 'v3_req',
			'config' => $conf_fname,
		);

		$csr = openssl_csr_new( $dn, $key, $options);
		openssl_csr_export($csr, $result);
		
		// Delete the config file
		unlink( $conf_fname);
		
		return $result;
	}

	public static function signCSR( $ca_key, $ca_password, $csr, $days, $csr_pass_attrs=true, $subject=null, $san=null, $ca_level=false, $exts=null)
	{
	}

	public static function validateCertificate( )
	{
	}
}
