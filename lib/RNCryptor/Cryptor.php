<?php
namespace RNCryptor;

class Cryptor {

	const DEFAULT_SCHEMA_VERSION = 3;

	protected $_settings;

	public function __construct() {
		if (!extension_loaded('mcrypt')) {
			throw new \Exception('The mcrypt extension is missing.');
		}
	}

	protected function _configureSettings($version) {

		$settings = new \stdClass();

		$settings->algorithm = MCRYPT_RIJNDAEL_128;
		$settings->saltLength = 8;
		$settings->ivLength = 16;

		$settings->pbkdf2 = new \stdClass();
		$settings->pbkdf2->prf = 'sha1';
		$settings->pbkdf2->iterations = 10000;
		$settings->pbkdf2->keyLength = 32;
		
		$settings->hmac = new \stdClass();
		$settings->hmac->length = 32;

		switch ($version) {
			case 0:
				$settings->mode = 'ctr';
				$settings->options = 0;
				$settings->hmac->includesHeader = false;
				$settings->hmac->algorithm = 'sha1';
				$settings->hmac->includesPadding = true;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 1:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = false;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 2:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = true;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = true;
				break;

			case 3:
				$settings->mode = 'cbc';
				$settings->options = 1;
				$settings->hmac->includesHeader = true;
				$settings->hmac->algorithm = 'sha256';
				$settings->hmac->includesPadding = false;
				$settings->truncatesMultibytePasswords = false;
				break;

			default:
				throw new \Exception('Unsupported schema version ' . $version);
		}

		$this->_settings = $settings;
	}

	/**
	 * Encrypt or decrypt using AES CTR Little Endian mode
	 */
	protected function _aesCtrLittleEndianCrypt($payload, $key, $iv) {

		$numOfBlocks = ceil(strlen($payload) / strlen($iv));
		$counter = '';
		for ($i = 0; $i < $numOfBlocks; ++$i) {
			$counter .= $iv;

			// Yes, the next line only ever increments the first character
			// of the counter string, ignoring overflow conditions.  This
			// matches CommonCrypto's behavior!
			$iv[0] = chr(ord($iv[0]) + 1);
		}

		return $payload ^ mcrypt_encrypt($this->_settings->algorithm, $key, $counter, 'ecb');
	}

	protected function _generateHmac(\stdClass $components, $hmacKey) {
	
		$hmacMessage = '';
		if ($this->_settings->hmac->includesHeader) {
			$hmacMessage .= $components->headers->version
							. $components->headers->options
							. (isset($components->headers->encSalt) ? $components->headers->encSalt : '')
							. (isset($components->headers->hmacSalt) ? $components->headers->hmacSalt : '')
							. $components->headers->iv;
		}

		$hmacMessage .= $components->ciphertext;

		$hmac = hash_hmac($this->_settings->hmac->algorithm, $hmacMessage, $hmacKey, true);

		if ($this->_settings->hmac->includesPadding) {
			$hmac = str_pad($hmac, $this->_settings->hmac->length, chr(0));
		}
	
		return $hmac;
	}

	/**
	 * Key derivation -- This method is intended for testing.  It merely
	 * exposes the underlying key-derivation functionality.
	 */
	public function generateKey($salt, $password, $version = self::DEFAULT_SCHEMA_VERSION) {
		$this->_configureSettings($version);
		return $this->_generateKey($salt, $password);
	}

	protected function _generateKey($salt, $password) {

		if ($this->_settings->truncatesMultibytePasswords) {
			$utf8Length = mb_strlen($password, 'utf-8');
			$password = substr($password, 0, $utf8Length);
		}

		$PBKDF2 = new PBKDF2();
		return $PBKDF2->hash($this->_settings->pbkdf2->prf, $password, $salt, $this->_settings->pbkdf2->iterations, $this->_settings->pbkdf2->keyLength, true);
	}

}


/**
 * Password hashing with PBKDF2.
 * (modified to use the native php function if available)
 * Based on the pure PHP implementation of PBKDF2 which can be found on:
 * https://defuse.ca/php-pbkdf2.htm
 *
 * @author havoc AT defuse.ca (www: https://defuse.ca/php-pbkdf2.htm)
 * @author TheBlintOne
 *
 * @license Public Domain (so feel free to use it): http://en.wikipedia.org/wiki/Public_domain
 */

/**
 * Class to encapsulate the PBKDF2 functions
 *
 * @author havoc AT defuse.ca (www: https://defuse.ca/php-pbkdf2.htm)
 * @author TheBlintOne
 */
class PBKDF2
{
	// These constants may be changed without breaking existing hashes.
	const PBKDF2_HASH_ALGORITHM = "sha256";
	const PBKDF2_ITERATIONS = 1000;
	const PBKDF2_SALT_BYTES = 24;
	const PBKDF2_HASH_BYTES = 24;

	const HASH_SECTIONS = 4;
	const HASH_ALGORITHM_INDEX = 0;
	const HASH_ITERATION_INDEX = 1;
	const HASH_SALT_INDEX = 2;
	const HASH_PBKDF2_INDEX = 3;

	/**
	 * Creates a hash for the given password
	 *
	 * @param string $password    the password to hash
	 * @return string             the hashed password in format "algorithm:iterations:salt:hash"
	 */
	public function create_hash( $password )
	{
		$salt = base64_encode( mcrypt_create_iv( PBKDF2::PBKDF2_SALT_BYTES, MCRYPT_DEV_URANDOM ) );
		return PBKDF2::PBKDF2_HASH_ALGORITHM . ":" . PBKDF2::PBKDF2_ITERATIONS . ":" .  $salt . ":" .
		base64_encode( $this->hash(
			PBKDF2::PBKDF2_HASH_ALGORITHM,
			$password,
			$salt,
			PBKDF2::PBKDF2_ITERATIONS,
			PBKDF2::PBKDF2_HASH_BYTES,
			true
		) );
	}

	/**
	 * Checks if the given password matches the given hash created by PBKDF::create_hash( string )
	 *
	 * @param string $password     the password to check
	 * @param string $good_hash    the hash which should be match the password
	 * @return boolean             true if $password and $good_hash match, false otherwise
	 *
	 * @see PBKDF2::create_hash
	 */
	public function validate_password( $password, $good_hash )
	{
		$params = explode( ":", $good_hash );
		if( count( $params ) < HASH_SECTIONS )
			return false;
		$pbkdf2 = base64_decode( $params[ PBKDF2::HASH_PBKDF2_INDEX ] );
		return slow_equals(
			$pbkdf2,
			$this->hash(
				$params[ PBKDF2::HASH_ALGORITHM_INDEX ],
				$password,
				$params[ PBKDF2::HASH_SALT_INDEX ],
				(int)$params[ PBKDF2::HASH_ITERATION_INDEX ],
				strlen( $pbkdf2 ),
				true
			)
		);
	}

	/**
	 * Compares two strings $a and $b in length-constant time
	 *
	 * @param string $a    the first string
	 * @param string $b    the second string
	 * @return boolean     true if they are equal, false otherwise
	 */
	public function slow_equals( $a, $b )
	{
		$diff = strlen( $a ) ^ strlen( $b );
		for( $i = 0; $i < strlen( $a ) && $i < strlen( $b ); $i++ )
		{
			$diff |= ord( $a[ $i ] ) ^ ord( $b[ $i ] );
		}
		return $diff === 0;
	}

	/**
	 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
	 *
	 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
	 *
	 * This implementation of PBKDF2 was originally created by https://defuse.ca
	 * With improvements by http://www.variations-of-shadow.com
	 * Added support for the native PHP implementation by TheBlintOne
	 *
	 * @param string $algorithm                                 the hash algorithm to use. Recommended: SHA256
	 * @param string $password                                  the Password
	 * @param string $salt                                      a salt that is unique to the password
	 * @param int $count                                        iteration count. Higher is better, but slower. Recommended: At least 1000
	 * @param int $key_length                                   the length of the derived key in bytes
	 * @param boolean $raw_output [optional] (default false)    if true, the key is returned in raw binary format. Hex encoded otherwise
	 * @return string                                           a $key_length-byte key derived from the password and salt,
	 *                                                          depending on $raw_output this is either Hex encoded or raw binary
	 * @throws Exception                                        if the hash algorithm are not found or if there are invalid parameters
	 */
	public function hash( $algorithm, $password, $salt, $count, $key_length, $raw_output = false )
	{
		$algorithm = strtolower( $algorithm );
		if( !in_array( $algorithm, hash_algos() , true ) )
			throw new Exception( 'PBKDF2 ERROR: Invalid hash algorithm.' );
		if( $count <= 0 || $key_length <= 0 )
			throw new Exception( 'PBKDF2 ERROR: Invalid parameters.' );

		// use the native implementation of the algorithm if available
		if( function_exists( "hash_pbkdf2" ) )
		{
			return hash_pbkdf2( $algorithm, $password, $salt, $count, $key_length, $raw_output );
		}

		$hash_length = strlen( hash( $algorithm, "", true ) );
		$block_count = ceil( $key_length / $hash_length );

		$output = "";
		for( $i = 1; $i <= $block_count; $i++ )
		{
			// $i encoded as 4 bytes, big endian.
			$last = $salt . pack( "N", $i );
			// first iteration
			$last = $xorsum = hash_hmac( $algorithm, $last, $password, true );
			// perform the other $count - 1 iterations
			for( $j = 1; $j < $count; $j++ )
			{
				$xorsum ^= ( $last = hash_hmac( $algorithm, $last, $password, true ) );
			}
			$output .= $xorsum;
		}

		if( $raw_output )
			return substr( $output, 0, $key_length );
		else
			return bin2hex( substr( $output, 0, $key_length ) );
	}
	}