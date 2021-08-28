<?php

ini_set('display_errors', 1); ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

spl_autoload_register(function($class_name){
	include("lib/vendor/$class_name.php");
});

function run_tests()
{
	$tests = 0; $passed = 0; $failed = array();

	{
		// Tests for bauth encryption / decryption
		$key_h   = '54686973497341546573744b65793031';
		$nonce_h = '4d5a6d68d3394a1ea83542efd512bbac';
		$cph_h   = 'be992e446bd9860f60a6c73294ae5fd1929f4eed0ebc1fd57946874476b1f889d7b93ce31aa64466e0e7a2ffe5c59056f4cdfd02a86f5497ca7b17747c024d53';
		$clr     = 'gueugneugneugneuse:tcoincoincoincoin13943249!@est';

		$key   = hex2bin( $key_h);
		$nonce = hex2bin( $nonce_h);
		$cph   = hex2bin( $nonce_h . $cph_h );

		// Test PublicKeyTicket::encrypt_bauth() with static values
		++$tests; 
		$cph_r   = PublicKeyTicket::encrypt_bauth( $clr, $key, $nonce);

		if( $nonce_h.$cph_h === bin2hex($cph_r) )
			++$passed;
		else
			$failed[] = "PublicKeyTicket::encrypt_bauth() with static values<br>Got<pre>".bin2hex($cph_r)."</pre>, expected <pre>".$nonce_h.$cph_h."</pre>";

		// Test PublicKeyTicket::decrypt_bauth() with static values
		++$tests;
		$clr_r = PublicKeyTicket::decrypt_bauth( $cph, $key);

		if( $clr_r === $clr )
			++$passed;
		else
			$failed[] = "PublicKeyTicket::decrypt_bauth() with static values<br>Got<pre>".bin2hex($clr_r)."</pre>, expected <pre>".bin2hex($clr)."</pre>";

		// Test PublicKeyTicket::decrypt_bauth(encrypt_bauth())
		++$tests;
		$clr_3 = PublicKeyTicket::decrypt_bauth( PublicKeyTicket::encrypt_bauth( $clr, $key), $key);
		if( $clr_3 === $clr )
			++$passed;
		else
			$failed[] = "PublicKeyTicket::decrypt_bauth(encrypt_bauth())<br>Got<pre>".bin2hex($clr_3)."</pre>, expected <pre>".bin2hex($clr)."</pre>";
	}

	do {
		// Class test
		$testkey = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx9Dlcz7xCmENeOIzKfRfHwuUXUTvffCv06e8KftgyvdVp945
cCh98LZbe9i/4pjy0W3OvqvMhR8+Jm5G/NMNbgPwtOIyXvd7gpQyeOeiqOfBjFbl
WuEZBsI+5nwZ+fVYeOFZL0smR7wB2mpGqcx2W2lJRw52l4a2XAm8RNYA6hNkRSCb
EaCHi3eynopj7UYPVlZYDmzrQa389U6aydGWmm5CkuwZKP+l9T6nGetP6Gv2ksX4
UL3VWxg6Xwv+mzYEyB0mBcnjzifaaWJXp7bW0bSes8lMGSFIIjhbi8TrN6AI3VRr
eQNyJP4gH8kKcVmTJqJuXah0t8KHI7ZmsB04kwIDAQABAoIBAQC7v5nJBswfz3+E
JS6j7jzug8fdN2e8s0nSm1nfLJcPPwVZ3SGlNDbZ1c7x+ICcHtCRXhcT64MZVnjk
TVwgNQL6a3Nh0uQ3fVytHiiqmCOrh0/CWOfa04TbZ+sIUHVr+08tDbjqCjem0Y4A
Nzm8VCSl0bELthhSWj7BDli7aUWkqfZsHURGaMqU1cWsPseHzZGbnRra7sFws3pT
+vvMBA0PX9BcKS5w7iXcFC4qDYFW8uppZRK2b1byX4RG12ci3uLoY093xNlWh2CA
OqpOlHmNrkf/J8rhZ5AUWzorthYdU+i6bDVSfTx+7sKIelfeAhgDJ9F9jfg2yGTr
Rz4OxqA5AoGBAPudWIdW23e6ebRoej/J50O28/SUnkN9hzGzn+Zk8neZ7Y5SyW9i
r9+8yrgHOudm1hTh3usla9VoEGReXQ+u3RqPB9f9KbALNeWxOEWZ7lTJqkcP0chx
kDfS+j8gBEKEhpUEJa6Jtdc20P4rfJXbESJl1s4wsWPrwnpH+ugdSputAoGBAMtM
b3JhGO0fFbh16Ixf+oVCm6DCAg3d3VKT4wdkzTDFwcuinmF6uuuW1cL0hn9LXpv8
JI7D/Ll204sP+I3ogpR2Ma3BGlrEfAj7yBCkvQu6Qjvhcf/gekvpm9jFIfO8iDsY
oYZ1k4J1xLq5bq5Db+4gc1biv20Adlm6OnW/Ya0/AoGBAKJQJXzhDiDVXY+A2mPt
9k8bZZKAkPvOrXjlfCAfPL7kwHdQdntxOS1m14sRtvDxyOadsrUUZdS8Fd75dKUa
U62/WPr/aHYVNUagJUHZBAMUONEwpk7c24D3i9FO8RCL91mH3FsUoQZdaUKdgPgW
4p3C/mfyx2xC+Sjy6Cv2QVvdAoGAf7rOarbGynS1WOf76/aBmCh5T0+VqtCytadl
BMg4g2Q8lozdpbFOr6ZdN9gaiO/5yVdqQKiyqHQYBU9Lgx2KrWx1Wg3xWQYKSDqp
QIvAmxWzd5v13CZVsExeNpvk8RaLIVYgZjKJM3Z63DaVa7fDI4IP9Y8RZpLbyRRQ
lppf7FECgYEAhw771xHG+e5T05ODokEG+pQQovwr/iH1lloVaLn58uY0ieJHy94Y
apsbvfpdW9s+1jP5tMIR4cFwmLUV4jr24XGHdF0vaTtfFXq8LSFzBVmEYn/KABNn
pnzqM0oCPzeSKRelvaZ7dXW7DhyyTGC/Zz4wE/PoHIZA/wdPEYGb+Q0=
-----END RSA PRIVATE KEY-----
EOF;

		$testpub = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9Dlcz7xCmENeOIzKfRf
HwuUXUTvffCv06e8KftgyvdVp945cCh98LZbe9i/4pjy0W3OvqvMhR8+Jm5G/NMN
bgPwtOIyXvd7gpQyeOeiqOfBjFblWuEZBsI+5nwZ+fVYeOFZL0smR7wB2mpGqcx2
W2lJRw52l4a2XAm8RNYA6hNkRSCbEaCHi3eynopj7UYPVlZYDmzrQa389U6aydGW
mm5CkuwZKP+l9T6nGetP6Gv2ksX4UL3VWxg6Xwv+mzYEyB0mBcnjzifaaWJXp7bW
0bSes8lMGSFIIjhbi8TrN6AI3VRreQNyJP4gH8kKcVmTJqJuXah0t8KHI7ZmsB04
kwIDAQAB
-----END PUBLIC KEY-----
EOF;

		$testseckey = <<<EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,D515AC9C2236A89E26DFC35B2D20A84B

GO/pp9eF6eM4gIyG9dRjW1TZ7IXVwlz75pbEoPV62yJJkxJBsHmCgJh+VcdwxzMZ
OrrieqbNYlTl7qMOBdIWPkAk62lt1NTlrKJw+ua70yidTSgZplOSsol8J9WujtQa
EUz5Ls5KQBvsE5UB2d36hX+jwOavKXfe6u+poY2NpoO8NSYnH5Pz0wDbuhmmIylS
EGGkZcv/GGayBXIhaK3LIwB4l8pC0cVEvC2AcD/OkBRfPzYm9/RsVG+dkj5hsiOx
BL4NdfPeavACMH1T1ub2QqsAIExJS2SY0pUJGCdo4FsRDVmAiqlvGSlsXEaSo62w
Y9Y/PpcDSBs4nNtbVRh7KykTs/S2Tz5w6grv1Di71970Hxi9wMMsy/Cum0gbU21Q
6ycrArgWA8ZzyIYsNbEVYgWLfbGBakmn967ovB4j5R1argpyix9ZBCgVefD5YqJf
u45Nx5+bVm/BbyoxAGFPVq7rmFc8QojsS7jlVY9jELDmpiPJA7HvT29bdFU+XHuo
RlyTrst0x6EZX4YJptPOcY2xFU/92jh5A+4BSN+ynRVTNcFYiRjkdI4PB9pIbGrI
H/MGeVNq12yjTqkefpPpHhaz48WX7HZszSQVp6Adhvo8lOoIbbB2jeGZXfXlvubS
pgiUYc54PgkOP0ywHc7x0ZFKzeL43NW6GDoaZoJ6Tg2cbyfFhMaYs62sepjKo6Wg
L2+lCP9UAmFhpMvrlsAAo/lAxm/biEFiR7LkhpsH+nowgpL1DuUqN61S8R+Lpssa
fZStPJwE91WPVkp6imTyfl28aiq60Sg00EsbLWYjIc/Y4k/04v9Sr8lItGHw0+SI
kBrBqsf7Db3pz/8QtFZLLNaCAk7X0SwHlHhETGfvBvweU7GPzZIKlkaflEAcIt2p
dxH+Nm3qplX4kCXTOUQum/HWSTSOFR6zzzjIGf+4O5ZqGKZ916+lwJ9ndF/Vsa5/
o+7OQ6Hqs5fJaavW5LEf7nOQKHb0+8q8wbXa2RF0hjbdDSZivf2dSgW0bYFF5a8d
yMOXS1WlsoXa6knM0OMxAgU1gcAiMLLme3rgrYY1T0xInGGPKovlxy6gGvs/jpmN
HCKX9gWmk1o8ev9zRJc6Neh9cYBIANJ/dJyzDy6yByrHG6SgQwzYKusL4LODVb9C
f8BxJlJ6G2+xITe6JAAzrqaaLQu+2ysoeNe3aS+YTz2uIvL//feHC/k0RlfhOSv/
TWO4IcnfKYyxKFivzk9hRv/WZti3jxSN1igj9c/36OHZW3oPMSJkYPaYL4f4TqiN
Yxzl+007Hvea61LaWzGlqPrV+DRmNdgMnRTk4slPPdEeYxfDxm/5fNgN4KDlFFdb
TWCMUhVCddKwiEtTNxrVw0fFtRykHjtP4CkgHAs6nxfp7P55d39qoaprvgLfXcsN
cqWPKZNUqkaVMM693o0Sn1Xhk9SgI6Oz5kCstec7kM0Ry/FL/zJriRq4c+6WZ44g
b5ipLySFfSaHIlvwvixUk+YoMLyOsYKmCUC/KTN5/Ko9skF46vDficYVYX7l46OB
+IaYp8ZIXqgDwhIc/7hrFKjb9UeuSJpW/16Wbg4yC/PgGWr877Uf/dTlQCRgWT6+
-----END RSA PRIVATE KEY-----
EOF;

		$testsecpub = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfNaepsdgIel8UGH+xog
3rklCbROif+W8tWbFoU04RmVgj+s9sl++VMKx2Z2Z/dz+zpuPAhbq8/pFby/V8JW
/jgE0Z2n3hYf+MRAYYXSSa+TuOq20TqbWcO2YKWOxP5G06jz1rj7Fa5KGhaylmg6
kmoHKR6TJvELPhjT599sRMVHnGIqLAFAi+Dg5/1vTJrzGZULHDfy00wX8yelmuBp
JMMJmr3zIvI1bb1gVwOh7Qs6x1EFtbuZAXHU0m9CfQB4UyiHSaGxAmf7IEld0svP
Jp5MZjhv4+JixIv5sfXF1AndQByd5UdK5EX81b4+FS+sFQSC2D+h4sC662CaWzno
vQIDAQAB
-----END PUBLIC KEY-----
EOF;
		$testecpub = <<<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTEKCTPSJIRUK21oWDh4s58icSA9
l+XskIEO5JX//ZJRpk7GsFNhFuBbQXkYflmABBBAAYhpAc5y7rJNeJlVsA==
-----END PUBLIC KEY-----
EOF;
                $testeckey = <<<EOF
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICNxMpApXY7Beqm9N7DE92YsMnEs6SSMVgOjWQi1eHqUoAoGCCqGSM49
AwEHoUQDQgAEiTEKCTPSJIRUK21oWDh4s58icSA9l+XskIEO5JX//ZJRpk7GsFNh
FuBbQXkYflmABBBAAYhpAc5y7rJNeJlVsA==
-----END EC PRIVATE KEY-----
EOF;
		// Test Instanciation
		++$tests;
		try { 
			$tkt = new PublicKeyTicket( 'sha1WithRSAEncryption', $testpub, $testkey); 
			unset( $tkt);
			++$passed;
		}
		catch(Exception $e) {
			$failed[] = 'Instanciation of PublicKeyTicket() rose an exception: <pre>'.$e->getMessage()."\n".$e->getTraceAsString().'</pre>';
			break;
		}

		// Generate a ticket
		++$tests;
		$ticket = '';
		try {
			$tkt = new PublicKeyTicket( 'sha1WithRSAEncryption', $testsecpub, $testseckey, 'testeuh');
			$args = array( 'uid' => 'emustermann', 'validuntil' => time()+86400);
			$ticket = $tkt->generate($args);
			unset($tkt);
			++$passed;
		}
		catch(Exception $e) {
			$failed[] = 'PublicKeyTicket()::generate() rose an exception: <pre>'.$e->getMessage()."\n".$e->getTraceAsString().'</pre>';
			break;
		}

		try {
			$tkt = new PublicKeyTicket( 'sha1WithRSAEncryption', $testsecpub);

			++$tests;
			if( $tkt->verify( $ticket) === true )
				++$passed;
			else
				$failed[] = 'PublicKeyTicket()::verify() didn\'t validate a valid signature.';
			unset($tkt);

			$tkt = new PublicKeyTicket( 'sha1WithRSAEncryption', $testpub);
			++$tests;
			if( $tkt->verify( $ticket) !== true )
				++$passed;
			else
				$failed[] = 'PublicKeyTicket()::verify() validated an invalid signature.';
			unset($tkt);

			$tkt = new PublicKeyTicket( 'sha1WithRSAEncryption', $testecpub, $testeckey);
			++$tests;
			$args = array( 'uid' => 'emustermann', 'validuntil' => time()+86400);
			$ticket2 = $tkt->generate($args);
			if( $tkt->verify( $ticket2) === true )
				++$passed;
			else
				$failed[] = 'PublicKeyTicket()::verify() didn\'t validate a valid signature with a prime256v1 EC key.';
			unset($tkt);
		}
		catch(Exception $e) {
			$failed[] = 'PublicKeyTicket()::verify() rose an exception: <pre>'.$e->getMessage()."\n".$e->getTraceAsString().'</pre>';
			break;
		}


	} while(false);

	// Test Report
	echo( "<br><br>Tests passed: $passed/$tests .<br>");
	if( count( $failed) != 0 )
	{
		echo("Failed tests: <br>");
		foreach( $failed as $evt )
		{
			echo(" - $evt<br>");
		}
	}
} 

run_tests();

