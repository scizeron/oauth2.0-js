var oauth2Utils = {
 'guid' : function() {
   function s4() {
    return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
   }
   return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
 },
 'newSessionItem' : function(value, ttl) {
   var item;
   if (typeof(ttl) != "undefined") {
    item = {
     v: value, 
     t: new Date().getTime(), 
     l: ttl * 1000
    };
   } else {
    item = {
     v: value
    };
   }
   return item;
 },
 'getParameter' : function(url, name) {
   name = name.replace(/[\[]/, '\\\[').replace(/[\]]/, '\\\]');
   var regexS = '[\\#&?/]' + name + '=([^&#]*)';
   var regex = new RegExp(regexS);
   var results = regex.exec(url);
   if (results != null) {
    return results[1];
   }
   return null;
 },
 'debug' : function(msg) {
   if (typeof(console) != "undefined") {
    console.log(msg);
   }
 }, 
 'error' : function(msg) {
   if (typeof(console) != "undefined") {
    console.error(msg);
   }
 },
 'setItem' : function(key, value) {
   var item = oauth2Utils.newSessionItem(value);
   var jsonItem = JSON.stringify(item);
   localStorage.setItem(key, jsonItem);
 },
 'getItem' : function(key) {
   var item;
   var jsonItem = localStorage.getItem(key);
   if (jsonItem == null) {
    return null;
   }
   return JSON.parse(jsonItem).v;
 }, 
 'setSessionItem' : function(key, value, ttl) {
   var item = oauth2Utils.newSessionItem(value, ttl);
   var jsonItem = JSON.stringify(item);
   sessionStorage.setItem(key, jsonItem);
 },
 'setSessionItemInStorage' : function(storage, key, value, ttl) {
   var item = oauth2Utils.newSessionItem(value, ttl);
   var jsonItem = JSON.stringify(item);
   storage.setItem(key, jsonItem);
 }, 
 'getSessionItem' : function(key) {
   var item;
   var jsonItem = sessionStorage.getItem(key);
   if (jsonItem == null) {
    return null;
   }
   item = JSON.parse(jsonItem);
   if (typeof(item.l) == "undefined") {
    return item.v;
   }
   if ((item.t + item.l) > new Date().getTime() ) {
    return item.v;
   }
   oauth2Utils.debug("\"" + key + "\" is expired");
   oauth2Utils.removeSessionItem(key);
   return null;
 },
 'removeSessionItem' : function(key) {
   sessionStorage.removeItem(key);
 },
 'clearSession' : function() {
   sessionStorage.clear();
 },
 'getAccessToken' : function(clientId) {
   return oauth2Utils.getSessionItem(clientId  + '.oauth2.accessToken');
 },
 'removeAccessToken' : function(clientId) {
   return oauth2Utils.removeSessionItem(clientId  + '.oauth2.accessToken');
 }      
};

var oauth2 = {
 'getExpiresInSecs' : function(clientId) {
   var jsonItem = sessionStorage.getItem(clientId + '.oauth2.accessToken');
   var item;
   if (jsonItem == null) {
    return 0;	   
   }
   item = JSON.parse(jsonItem);
   if (typeof(item.l) == "undefined") {
	return 0;
   }
   var remainingTimeInMillis = item.t + item.l - new Date().getTime();
   if (remainingTimeInMillis > 0) {
    return remainingTimeInMillis / 1000;
   }
   return 0;
  },
 'getAccessToken' : function(clientId, successCallback, errorCallback) {
   var accessToken = oauth2Utils.getAccessToken(clientId);
   var accessTokenOrigin = 'session';
   var stateOk = true;
   var expiresIn = null;
   var stateParameter;
   var stateSession;
   var errorDescription;
   var error;
   
   if (accessToken == null) {
    accessToken = oauth2Utils.getParameter(window.location, 'access_token');
    accessTokenOrigin = 'request';
   }
     
   if (accessToken == null) {
	oauth2Utils.debug('no session/request access_token');
	error = oauth2Utils.getParameter(window.location, 'error');
	if (error != null) {
	 oauth2Utils.debug('error parameter detected : ' + error);
	 if (typeof(errorCallback) != 'undefined') {
	  errorDescription = oauth2Utils.getParameter(window.location, 'error_description'); 
	  errorCallback(errorDescription != null ? errorDescription : error);
	 }
	}
	return null;   
   }
   
   oauth2Utils.debug('use access_token from '  + accessTokenOrigin + ' : ' + accessToken);
    
   if (accessTokenOrigin == 'request') {
    stateParameter = oauth2Utils.getParameter(window.location, 'state');
    stateSession = oauth2Utils.getSessionItem(clientId + '.oauth2.state'); 
    oauth2Utils.removeSessionItem(clientId + '.oauth2.state');
    
    // IE issue, stateSession may be null ...
    if (stateSession != null && stateParameter != stateSession) {
     oauth2Utils.error(stateSession + ' <> ' + stateParameter);
     oauth2Utils.error('The state validation has failed [expected: ' + stateSession + ', received: ' + stateParameter + '], it\'s a security problem !!!');
     if (typeof(errorCallback) != 'undefined') {
       oauth2Utils.debug('Call errorCallback ...');
       errorCallback('The state check is failed');
     }
     return null;
    }
   
    expiresIn = oauth2Utils.getParameter(window.location, 'expires_in');
    oauth2Utils.setSessionItem(clientId + '.oauth2.accessToken', accessToken, expiresIn);
    oauth2Utils.removeSessionItem(clientId + '.oauth2.accessToken.tmp');
    
   } else if (accessTokenOrigin == 'session') {
	expiresIn = oauth2.getExpiresInSecs(clientId); 
   }
   
   if (typeof(successCallback) != 'undefined') {
   	 oauth2Utils.debug('Call successCallback ...');
   	 successCallback(accessToken, expiresIn, accessTokenOrigin);   
   }
   
   return accessToken;
 },
 'getAuthorizeRequest' : function(clientId, scopes, authorizeUrl, redirectUri) {
   var expiresIn = oauth2.getExpiresInSecs(clientId);
   var accessToken = oauth2Utils.getSessionItem(clientId + '.oauth2.accessToken');
   oauth2Utils.removeAccessToken(clientId);
   oauth2Utils.setSessionItem(clientId + '.oauth2.accessToken.tmp', accessToken, expiresIn * 1000);
   
   var state = oauth2Utils.guid();
   oauth2Utils.setSessionItem(clientId + '.oauth2.state', state);
   
   var url = authorizeUrl + '?client_id=' + encodeURIComponent(clientId) 
	 	  				  + '&response_type=token'
	 	  				  + '&state=' + encodeURIComponent(state)
	 	  				  ;
  
   if (scopes != '') {
    url = url + '&scope=' + encodeURIComponent(oauth2Cfg.scopes);
   } else {
    oauth2Utils.debug('no scope is requested');  
   }
   
   url = url + '&redirect_uri=' + encodeURIComponent(redirectUri)
   
   oauth2Utils.debug('---------------------------------------------------------------');
   oauth2Utils.debug('  authorize');
   oauth2Utils.debug('---------------------------------------------------------------');
   oauth2Utils.debug('- request       : ' + url);
   oauth2Utils.debug('- redirect_uri  : ' + redirectUri);
   oauth2Utils.debug('---------------------------------------------------------------');
    
   return url;
 },
 'authorize' : function(clientId, scopes, authorizeUrl, redirectUri) {
   window.location.replace(oauth2.getAuthorizeRequest(clientId, scopes, authorizeUrl, redirectUri, prompt));  
 } 
}