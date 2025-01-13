<?php
// Hash a password using a salt and SHA-256
function getPasswordHash_Hex($username, $password) {
    // Compute hash of salted-password (and salt) from username and password (in hex format)
    $salt = hash('sha256', $username);	// Compute salt as the hash of the username
    $saltedPwd = $salt . $password;		// Get a salted password by combining salt and password
    $hashedPwd = hash('sha256', $saltedPwd);	// Hash the salted password using SHA-256
    // Return the password hash and the salt
    return [
        'hash' => $hashedPwd,
        'salt' => $salt
    ];
}
?>