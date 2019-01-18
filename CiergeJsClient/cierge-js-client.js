"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var CiergeJsClient = /** @class */ (function () {
    function CiergeJsClient() {
        var href = "https://localhost:9000/connect/authorize?response_type=token&client_id=client-app&redirect_uri=http://localhost:8000/signin-oidc&scope=openid&state=skdhrghyiousdrhbg&nonce=sdfgtjhdfgjdfg&prompt=none";
        setTimeout(function () { return window.location.href = href; }, 0);
    }
    return CiergeJsClient;
}());
exports.CiergeJsClient = CiergeJsClient;
//# sourceMappingURL=cierge-js-client.js.map