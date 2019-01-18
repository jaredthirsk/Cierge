export class CiergeJsClient {
	
	constructor(){
	  let href = "https://localhost:9000/connect/authorize?response_type=token&client_id=client-app&redirect_uri=http://localhost:8000/signin-oidc&scope=openid&state=skdhrghyiousdrhbg&nonce=sdfgtjhdfgjdfg&prompt=none";
	  setTimeout(()=> window.location.href = href,0);
	}
	

   }
