<?php

	function calc_salted_pw($password,$salt,$algo,$rounds){
	
		$salt=base64_decode($saltbase);

		return hash_pbkdf2($algo,$password,$salt,$rounds, 0 , true);
	}
	function calc_scram_stored_key_base64($password,$salt,$algo='sha1',$rounds=4096){
	
		$salted_pw = calc_salted_pw($password,$salt,$algo,$rounds);
		$client_key = hash_hmac($algo,"Client Key",$salted_pw,true);

		$stored_key = hash($algo,$client_key,true);
	
		return base64_encode($stored_key);
	}
	function calc_scram_server_key_base64($password,$salt,$algo='sha1',$rounds=4096){

		$salted_pw = calc_salted_pw($password,$salt,$algo,$rounds);
		$server_key = hash_hmac('sha1',"Server Key",$salted_pw,true);

		return base64_encode($server_key);
	}
	
	function calc_scram($password,$salt,$rounds=4096,$algo = 'sha1'){
		$scram = array();
		$scram['salt'] = $salt;
		$scram['server_key'] = calc_scram_server_key_base64($password,$salt,$algo,$rounds);
		$scram['stored_key'] = calc_scram_stored_key_base64($password,$salt,$algo,$rounds);
		$scram['rounds'] = $rounds;
		$scram['pwhash'] = 'scram-'. $algo;

		return $scram;
	}
	function generate_scram($password,$rounds=4096,$algo='sha1'){
		$salt = base64_encode( hash($algo,mcrypt_create_iv(256),true));
		return calc_scram($password,$salt,$rounds,$algo);
	}

?>
