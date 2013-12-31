<?php

require_once __DIR__ . '/VectorBase.php';

/**
 * THIS CLASS IS DYNAMICALLY GENERATED BY ../render-vector-tests.php.
 * IF YOU NEED TO MAKE CHANGES, DO IT IN THAT SCRIPT, OR IN THE VectorBase
 * CLASS WHICH THIS CLASS EXTENDS.  RE-RENDERING THIS CLASS ONLY NEEDS TO
 * HAPPEN WHEN THE CONTENTS OF ../../../vectors/ CHANGE.
 */
class PasswordVectors extends VectorBase {

	public static function main() {
		$suite  = new PHPUnit_Framework_TestSuite(get_called_class());
		PHPUnit_TextUI_TestRunner::run($suite);
	}
	
	public function testAllFieldsEmptyOrZero() {
		$vector = json_decode('{"title":"All fields empty or zero","version":"3","password":"","enc_salt":"0000000000000000","hmac_salt":"0000000000000000","iv":"00000000000000000000000000000000","plaintext":"","ciphertext":"03010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000e73c 3a20a905 8bbd1622 2b2d52f3 94ebe0f2 90c2290c 3b4ce61e e9b7b73f 593ef584 c5053156 1822bf00 567c2838 f546"}', true);
		$this->_runPasswordTest($vector);

	}

	public function testOneByte() {
		$vector = json_decode('{"title":"One byte","version":"3","password":"thepassword","enc_salt":"0001020304050607","hmac_salt":"0102030405060708","iv":"02030405060708090a0b0c0d0e0f0001","plaintext":"a","ciphertext":"03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001de17 cb07d089 c061385c 20fd3d47 74c717ba fac9d70f ce79f56a 6f65c1a7 cd790b15 6b8aef33 6227a442 3ce79ae5 abce"}', true);
		$this->_runPasswordTest($vector);

	}

	public function testExactlyOneBlock() {
		$vector = json_decode('{"title":"Exactly one block","version":"3","password":"thepassword","enc_salt":"0102030405060700","hmac_salt":"0203040506070801","iv":"030405060708090a0b0c0d0e0f000102","plaintext":"0123456789abcdef","ciphertext":"03010102 03040506 07000203 04050607 08010304 05060708 090a0b0c 0d0e0f00 01020e43 7fe80930 9c03fd53 a475131e 9a1978b8 eaef576f 60adb8ce 2320849b a32d7429 00438ba8 97d22210 c76c35c8 49df"}', true);
		$this->_runPasswordTest($vector);

	}

	public function testMoreThanOneBlock() {
		$vector = json_decode('{"title":"More than one block","version":"3","password":"thepassword","enc_salt":"0203040506070001","hmac_salt":"0304050607080102","iv":"0405060708090a0b0c0d0e0f00010203","plaintext":"0123456789abcdef 01234567","ciphertext":"03010203 04050607 00010304 05060708 01020405 06070809 0a0b0c0d 0e0f0001 0203e01b bda5df2c a8adace3 8f6c588d 291e03f9 51b78d34 17bc2816 581dc6b7 67f1a2e5 7597512b 18e1638f 21235fa5 928c"}', true);
		$this->_runPasswordTest($vector);

	}

	public function testMultibytePasswordAndText() {
		$vector = json_decode('{"title":"Multibyte password and text","version":"3","password":"\u4e2d\u6587\u5bc6\u7801","enc_salt":"0304050607000102","hmac_salt":"0405060708010203","iv":"05060708090a0b0c0d0e0f0001020304","plaintext":"\u4e00\u70b9\u4e2d\u6587\u3002","ciphertext":"03010304 05060700 01020405 06070801 02030506 0708090a 0b0c0d0e 0f000102 030407f1 a50eef3f 48ad4638 56d79751 e604d107 e6e3cf01 01f29287 67083c95 16d94982 d9fdd5a8 1b2b369c da9d781a 43a3"}', true);
		$this->_runPasswordTest($vector);

	}

	public function testLongerTextAndPassword() {
		$vector = json_decode('{"title":"Longer text and password","version":"3","password":"It was the best of times, it was the worst of times; it was the age of wisdom, it was the age of foolishness;","enc_salt":"0405060700010203","hmac_salt":"0506070801020304","iv":"060708090a0b0c0d0e0f000102030405","plaintext":"it was the epoch of belief, it was the epoch of incredulity; it was the season of Light, it was the season of Darkness; it was the spring of hope, it was the winter of despair; we had everything before us, we had nothing before us; we were all going directly to Heaven, we were all going the other way.","ciphertext":"03010405 06070001 02030506 07080102 03040607 08090a0b 0c0d0e0f 00010203 0405566a 6bfc6076 2ab72296 5a6a3d33 d1bb40e7 2728040d 057dc4c1 98a068de 6708e7ad 8c500232 1539a0eb a2c8fd96 aef950ae ccc647cf e54a82f9 1ad67014 94f6bc5d 701e3db6 92b04fec 47b792f0 9b76e8f5 8ba94f81 b44d54ba b3b30a00 4924af0b 651f72ef 083a3efd 768d7f34 a106a4a5 cfc7417a f1f37524 3162e90f 3f43df76 c9b9e784 c0126cea f4dcc60c c28bacce 1bbd9658 69ff334a 3f60e4a0 5924"}', true);
		$this->_runPasswordTest($vector);

	}



}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == 'PasswordVectors::main') {
	PasswordVectors::main();
}
