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


// function login(e) {
// 	e.preventDefault();
// 	var replay_token = $('.replay').data()['replay']
// 	var email = $('#email').val()
// 	var password = $('#password').val()
// 	var data = {'email': email, 'password': password, 'replay_token': replay_token,};
// 	$.ajax({
// 		url: "/login",
// 		type: 'POST',
// 		data: JSON.stringify(data),
// 		contentType: "application/json; charset=utf-8",
// 		success: function(data) {
// 			if (data == '1'){
// 				alert('Login is unsuccesful');
// 			}

// 			else{
// 				var blob = new Blob([key], {type: "text/plain;charset=utf-8"});
// 	  			saveAs(blob, 'key.txt');
// 			}
// 			window.location = 'https://'+window.location.hostname+ ':'+ window.location.port + '/home'
// 		},
// 		error: function() { console.log(data); }
// 	});
// }


function yooo(e) {

	e.preventDefault();
	var hmac = $('.hmac').data()['hmac'];
	var title = $('#title').val();
	var key = $('#key').val();
	var title_encrypted = encrypt(title, key)
	var content = $('#content').val();
	var content_encrypted = encrypt(content, key)
	var replay_token = $('.hmac').data()['replay'];
	var data = {'title': title, 'content': content, 'hmac': hmac, 'content_encrypted': content_encrypted, 'title_encrypted' : title_encrypted, 'replay_token': replay_token};
	var hash = CryptoJS.HmacSHA256(title+content, hmac);
	var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);	
	data['hash'] = hashInBase64;
	console.log(data)

	if (!title || !content || !key){
		return
	}

	$.ajax({
		url: "/post/new",
		type: 'POST',
		data: JSON.stringify(data),
		contentType: "application/json; charset=utf-8",
		success: function(data) {
			if (data == '1'){
				alert('Title is already in use!');
			}
			else if (data == '2'){
				alert('Content is already in use!');
			}
			else if (data == '3'){
				alert('REplay attack!');
			}
			else{
				var blob = new Blob([key], {type: "text/plain;charset=utf-8"});
	  			saveAs(blob, 'key.txt');
			}
			window.location = 'https://'+window.location.hostname+ ':'+ window.location.port + '/home'
		},
		error: function() { console.log(data); }
	});
}

if ($('.hmac').data())
	{
		$('#key').prop("disabled", "disabled");
	}

var keySize = 256;
var ivSize = 128;
var iterations = 100;


function encrypt (msg, pass) {
  var salt = CryptoJS.lib.WordArray.random(128/8);
  
  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: keySize/32,
      iterations: iterations
    });

  var iv = CryptoJS.lib.WordArray.random(128/8);
  
  var encrypted = CryptoJS.AES.encrypt(msg, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
    
  });
  
  // salt, iv will be hex 32 in length
  // append them to the ciphertext for use  in decryption
  var transitmessage = salt.toString()+ iv.toString() + encrypted.toString();
  return transitmessage;
}

function decrypt (transitmessage, pass) {
  var salt = CryptoJS.enc.Hex.parse(transitmessage.substr(0, 32));
  var iv = CryptoJS.enc.Hex.parse(transitmessage.substr(32, 32))
  var encrypted = transitmessage.substring(64);
  
  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: keySize/32,
      iterations: iterations
    });

  var decrypted = CryptoJS.AES.decrypt(encrypted, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
    
  })
  return decrypted;
}



function callme(e){
	alert('s');
	e.preventDefault();
	var key = $('#key').val();
	var data = $("#hidden-data-for-decryption").data();
	try {
		var title = decrypt(data['title'], key).toString(CryptoJS.enc.Utf8);
		var content = decrypt(data['content'], key).toString(CryptoJS.enc.Utf8);
		var post_id =$('.hidden-key').data()['postnumber'];
		console.log(title, content);
		var data = {'title': title, 'content': content, 'post_id': post_id}
		if (title){
			if (content){
				viewPost(post_id);
				// window.location = 'https://'+window.location.hostname+ ':'+ window.location.port + '/post/'+post_id+'/1'
			}
		}
	}
	catch(err) {
		alert('Try again');
	}

	// var blob = new Blob(['title: ' +  title + '\ncontent: ' + content], {type: "text/plain;charset=utf-8"});
	// saveAs(blob, 'answer.txt');


}



function viewPost(post_id) {
	var url = post_id;
	var form = $('<form action="' + url + '" method="post">' +
	'<input type="text" name="api_url" value="' + post_id + '" />' +
	'</form>');
	$('body').append(form);
	form.submit();
}