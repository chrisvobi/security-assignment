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

function getPasswordHash_Bin($username, $password) {
    $salt = hash('sha256', $username, true);	// Compute salt as the hash of the username (parameter 'true' computes hash in bin format, default is hex)
    $saltedPwd = $salt . $password;				// Get a salted password by combining salt and password
    $hashedPwd = hash('sha256', $saltedPwd, true);	// Hash the salted password using SHA-256
    // Return the password hash and the salt
    return [
        'hash' => $hashedPwd,
        'salt' => $salt
    ];
}

function deriveEncryptionKey($username, $password) {
    // Compute binary hash of salted-password (and salt) from username and password
    $pwdHash = getPasswordHash_Bin($username, $password);

    // Derive a secure key using PBKDF2
    $iterations = 100000; // Number of iterations for PBKDF2
    $keyLength = 32; // Key length = 32 bytes for AES-256
    $key = hash_pbkdf2('sha256', $pwdHash['hash'], $pwdHash['salt'], $iterations, $keyLength, true); // Parameter 'true' computes hash_pbkdf2 in bin
    return $key;
}

// Encrypt data using AES-256-GCM
function encryptData($data, $key) {
    $nonce = random_bytes(8); // use 8 bytes instead of 12 for nonce
    $cipher = "aes-256-gcm";

    // Encrypt the data
    $ciphertext = openssl_encrypt($data, $cipher, $key, OPENSSL_RAW_DATA, $nonce, $tag);

    // set tag to 8 bytes
    $tag = substr($tag, 0, 8);

    // Concatenate nonce, tag, and ciphertext for storage
    $result = $nonce . $tag . $ciphertext;
    return base64_encode($result); // Encode to make it suitable for storage or transmission
}

// Decrypt data using AES-256-GCM, extracting nonce, tag, and ciphertext from the concatenated string
function decryptData($encryptedData, $key) {
    $cipher = "aes-256-gcm";

    // Decode the base64-encoded data
    $encryptedData = base64_decode($encryptedData);

    // Extract nonce (8 bytes), tag (8 bytes), and ciphertext
    $nonce = substr($encryptedData, 0, 8);
    $tag = substr($encryptedData, 8, 8);
    $ciphertext = substr($encryptedData, 16);

    // Decrypt the data
    $decryptedData = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $nonce, $tag);

    return $decryptedData;
}
?>