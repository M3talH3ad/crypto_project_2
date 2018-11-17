function generate_key() {
	$.ajax({
		url: "/generate/key",
		type: 'GET',
		success: function(res) {
			var ta = document.getElementById('key');
			ta.value = res;
		}
	});
}

function yooo(e) {

	e.preventDefault();
	var hmac = $('.hmac').data()['hmac'];
	var title = $('#title').val();
	var key = $('#key').val();
	var content = $('#content').val();
	var data = {'title': title, 'content': content, 'key': key, 'hmac': hmac};

	var hash = CryptoJS.HmacSHA256(title+content+key, hmac);
	var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);	
	data['hash'] = hashInBase64;

	$.ajax({
		url: "/post/new",
		type: 'POST',
		data: JSON.stringify(data),
		contentType: "application/json; charset=utf-8",
		// dataType: "json",
		success: function(data) {
			// alert(data);
			var blob = new Blob([data], {type: "text/plain;charset=utf-8"});
  			saveAs(blob, 'key.txt');
			window.location = 'https://'+window.location.hostname+ ':'+ window.location.port + '/home'
		},
		error: function() { console.log(data); }
	});
}

// yooo
// function rsa_encrypt(argument) {
// 	var publicKey = forge.pki.publicKeyFromPem(argument);
// 	var secretMessage = “user input goes here”;
// 	var encrypted = publicKey.encrypt(secretMessage, "RSA-OAEP", {
// 		md: forge.md.sha256.create(),
// 		mgf1: forge.mgf1.create()
// 	});
// 	var base64 = forge.util.encode64(encrypted);
// }