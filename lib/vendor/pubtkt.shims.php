<?php


function pubtkt_generate($privkeyfile, $privkeytype, $digest, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata, $bauth = null, $multifactor = false) 
{
}

function pubtkt_generate_php($privkey, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata, $bauth = null)
{
}

function pubtkt_verify($pubkeyfile, $pubkeytype, $digest, $ticket)
{
}

function pubtkt_verify_php($pubkey, $ticket)
{
}

/*  Parse a ticket into its key/value pairs and return them as an
 *  associative array for easier use.
 */
function pubtkt_parse($ticket)
{
}

/*  Encrypt a "bauth" passthru basic authentication value
 *  (username:password) with the given key (must be exactly 16
 *  characters and match the key configured on the server). The
 *  result is in binary, but can be passed to pubtkt_generate()
 *  directly, as it will be Base64-encoded.
 */
function pubtkt_encrypt_bauth($bauth, $key)
{
}

/*  Decrypt a "bauth" passthru basic authentication value
 *  and return only the password with the given key (must be exactly 16
 *  characters). The input $bauth string should be binary,
 *  so it has to be decoded using base64_decode beforehand.
 */
function pubtkt_decrypt_bauth($bauth, $key)
{
}
