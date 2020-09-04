$(document).ready(function() {

    var modulus = "ebd99e33d31ec3bb8e4f6c8f86bed43097fe73b59df6c86dfac375283617bb71d0a10a00938d36dfe7b525176ea0748878437d7bfff7b71533484bd7573c0544adb5b11ebb9a43018868b45914c7af946cb70d3ecb54869ee5b9ea1f92257a2ac412c841f3f64ef72200dc960f132a8baa1b0ee6ac0ab5bf0a1c0b34edb07f67";
    var publicExp = "10001";
    var privateExp = "9ed0cca233411d2697fecda89c60b5fbfeedbe370726ddf28910c33c8fa84d75a7ba39450816e863bfe09018864b100db18628e2ae0bbdc24de51a04e8de26e0bc563ed3cbfae3cff7e18390ceaa8d5271623826d1d9bf38fee903d80fa89619dddd8cee9e89d7564080b8b1c616fc7396de530b2455b993cdbc8439b509f2b9";
    var primeP = "fcad444376c71dd40ce3aae1a6e712a13ab184cba3c1e2a57f4291fdd9ad85192f7d5f34c987e900fcaa3c85accf1e9aaa9bf341f76d271a9f6fa1b0d19bd905";
    var primeQ = "eef3b296ca4b4119286b3867d73fb51dd9e8615cf1609e6c9b0736ce177bd6e9b483e609705755a7944968dd8eb9b294b12c51615c4d9c0b8b20b28c586f727b";
    var primeExpP = "4ac6f033d2fbfc6cdbdfa89b9d2c374c35b5816a4ead3b68e4ef8b8b07979d932585c1de3a621967ac5ea9089a6ab550ea7aba93e4288e71078c1edad83d7a0d";
    var primeExpQ = "652d9f432629334959c9fcba4b745856697c722d8eaf60a590073ff7880e11f427516a4838df620f71449c38a444910f50edf90f86abfe150d362d242c16149d";
    var crtCoeff = "38c1148d720ad76c43c3de9069b307a9fbb2b99c68880d29b6892e758fda3d30cec45713dd35c1965c169279423e7b46ffd0d08555e3c56e12f0803c2fc46445";

    var x509PublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDr2Z4z0x7Du45PbI+GvtQwl/5ztZ32yG36w3Uo\n" +
			            "Nhe7cdChCgCTjTbf57UlF26gdIh4Q317//e3FTNIS9dXPAVErbWxHruaQwGIaLRZFMevlGy3DT7L\n" +
			            "VIae5bnqH5IleirEEshB8/ZO9yIA3JYPEyqLqhsO5qwKtb8KHAs07bB/ZwIDAQAB";

	var pkcs1PrivateKey = "MIICXAIBAAKBgQDr2Z4z0x7Du45PbI+GvtQwl/5ztZ32yG36w3UoNhe7cdChCgCTjTbf57UlF26g\n" +
			            "dIh4Q317//e3FTNIS9dXPAVErbWxHruaQwGIaLRZFMevlGy3DT7LVIae5bnqH5IleirEEshB8/ZO\n" +
			            "9yIA3JYPEyqLqhsO5qwKtb8KHAs07bB/ZwIDAQABAoGBAJ7QzKIzQR0ml/7NqJxgtfv+7b43Bybd\n" +
			            "8okQwzyPqE11p7o5RQgW6GO/4JAYhksQDbGGKOKuC73CTeUaBOjeJuC8Vj7Ty/rjz/fhg5DOqo1S\n" +
			            "cWI4JtHZvzj+6QPYD6iWGd3djO6eiddWQIC4scYW/HOW3lMLJFW5k828hDm1CfK5AkEA/K1EQ3bH\n" +
			            "HdQM46rhpucSoTqxhMujweKlf0KR/dmthRkvfV80yYfpAPyqPIWszx6aqpvzQfdtJxqfb6Gw0ZvZ\n" +
			            "BQJBAO7zspbKS0EZKGs4Z9c/tR3Z6GFc8WCebJsHNs4Xe9bptIPmCXBXVaeUSWjdjrmylLEsUWFc\n" +
			            "TZwLiyCyjFhvcnsCQErG8DPS+/xs29+om50sN0w1tYFqTq07aOTvi4sHl52TJYXB3jpiGWesXqkI\n" +
			            "mmq1UOp6upPkKI5xB4we2tg9eg0CQGUtn0MmKTNJWcn8ukt0WFZpfHItjq9gpZAHP/eIDhH0J1Fq\n" +
			            "SDjfYg9xRJw4pESRD1Dt+Q+Gq/4VDTYtJCwWFJ0CQDjBFI1yCtdsQ8PekGmzB6n7srmcaIgNKbaJ\n" +
			            "LnWP2j0wzsRXE901wZZcFpJ5Qj57Rv/Q0IVV48VuEvCAPC/EZEU=";

    var pkcs8PrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOvZnjPTHsO7jk9sj4a+1DCX/nO1\n" +
			            "nfbIbfrDdSg2F7tx0KEKAJONNt/ntSUXbqB0iHhDfXv/97cVM0hL11c8BUSttbEeu5pDAYhotFkU\n" +
			            "x6+UbLcNPstUhp7lueofkiV6KsQSyEHz9k73IgDclg8TKouqGw7mrAq1vwocCzTtsH9nAgMBAAEC\n" +
			            "gYEAntDMojNBHSaX/s2onGC1+/7tvjcHJt3yiRDDPI+oTXWnujlFCBboY7/gkBiGSxANsYYo4q4L\n" +
			            "vcJN5RoE6N4m4LxWPtPL+uPP9+GDkM6qjVJxYjgm0dm/OP7pA9gPqJYZ3d2M7p6J11ZAgLixxhb8\n" +
			            "c5beUwskVbmTzbyEObUJ8rkCQQD8rURDdscd1AzjquGm5xKhOrGEy6PB4qV/QpH92a2FGS99XzTJ\n" +
			            "h+kA/Ko8hazPHpqqm/NB920nGp9vobDRm9kFAkEA7vOylspLQRkoazhn1z+1HdnoYVzxYJ5smwc2\n" +
			            "zhd71um0g+YJcFdVp5RJaN2OubKUsSxRYVxNnAuLILKMWG9yewJASsbwM9L7/Gzb36ibnSw3TDW1\n" +
			            "gWpOrTto5O+LiweXnZMlhcHeOmIZZ6xeqQiaarVQ6nq6k+QojnEHjB7a2D16DQJAZS2fQyYpM0lZ\n" +
			            "yfy6S3RYVml8ci2Or2ClkAc/94gOEfQnUWpION9iD3FEnDikRJEPUO35D4ar/hUNNi0kLBYUnQJA\n" +
			            "OMEUjXIK12xDw96QabMHqfuyuZxoiA0ptokudY/aPTDOxFcT3TXBllwWknlCPntG/9DQhVXjxW4S\n" +
			            "8IA8L8RkRQ==";
                          
	var rsaKey = new RSAKey();
	rsaKey.setPrivateEx(modulus, publicExp, privateExp, primeP, primeQ, primeExpP, primeExpQ, crtCoeff);

	test("writing public key to x509 format", function() {
		var x509Key = rsaKey.publicKeyToX509PemString();
		equal(_rsa_splitKey(x509Key, 76), x509PublicKey, "Output key should be same as expected key.");
	});
	
	test("reading public key from x509 format", function() {
		var readKey = new RSAKey();
		readKey.readPublicKeyFromX509PEMString(x509PublicKey);
		equal("" + rsaKey.n, "" + readKey.n, "Modulus should be same as expected modulus.");
		equal("" + rsaKey.e, "" + readKey.e, "Public exponent should be same as expected public exponent.");
	});
	
	test("writing private key to PKCS#1 format", function() {
		var pemKey = rsaKey.privateKeyToPkcs1PemString();
		equal(_rsa_splitKey(pemKey, 76), pkcs1PrivateKey, "Output key should be same as expected key.");
	});
	
	test("reading private key from PKCS#1 format", function() {
		var readKey = new RSAKey();
		readKey.readPrivateKeyFromPkcs1PemString(pkcs1PrivateKey);
		equal("" + rsaKey.n, "" + readKey.n, "Modulus should be same as expected modulus.");
		equal("" + rsaKey.e, "" + readKey.e, "Public exponent should be same as expected public exponent.");
		equal("" + rsaKey.p, "" + readKey.p, "Prime P should be same as expected prime P.");
		equal("" + rsaKey.q, "" + readKey.q, "Prime Q should be same as expected prime Q.");
		equal("" + rsaKey.dmp1, "" + readKey.dmp1, "Prime P exp should be same as expected prime P exp.");
		equal("" + rsaKey.dmp2, "" + readKey.dmp2, "Prime Q exp should be same as expected prime Q exp.");
		equal("" + rsaKey.coeff, "" + readKey.coeff, "Coeff should be same as expected coeff.");
	});
	
	test("writing private key to PKCS#8 format", function() {
		var pemKey = rsaKey.privateKeyToPkcs8PemString();
		equal(_rsa_splitKey(pemKey, 76), pkcs8PrivateKey, "Output key should be same as expected key.");
	});
	
	test("reading private key from PKCS#8 format", function() {
		var readKey = new RSAKey();
		readKey.readPrivateKeyFromPkcs8PemString(pkcs8PrivateKey);
		equal("" + rsaKey.n, "" + readKey.n, "Modulus should be same as expected modulus.");
		equal("" + rsaKey.e, "" + readKey.e, "Public exponent should be same as expected public exponent.");
		equal("" + rsaKey.p, "" + readKey.p, "Prime P should be same as expected prime P.");
		equal("" + rsaKey.q, "" + readKey.q, "Prime Q should be same as expected prime Q.");
		equal("" + rsaKey.dmp1, "" + readKey.dmp1, "Prime P exp should be same as expected prime P exp.");
		equal("" + rsaKey.dmp2, "" + readKey.dmp2, "Prime Q exp should be same as expected prime Q exp.");
		equal("" + rsaKey.coeff, "" + readKey.coeff, "Coeff should be same as expected coeff.");
	});

});
