(function ()
{
    'use strict';

    function Authenticator($http, $rootScope, $window, authService, Base64, gettextCatalog)
    {
        function setupAuthorizationHeader(data)
        {
            $http.defaults.headers.common.Authorization = 'Token ' + Base64.encode(data);
            authService.loginConfirmed(null, function (config)
            {
                angular.extend(config.headers, {Authorization: $http.defaults.headers.common.Authorization});
                return config;
            });
        }

        /**
         * initialize to whatever is in the cookie, if anything
         */
        var cookieAuthdata = $window.$.cookie('token');
        if (cookieAuthdata) {
            setupAuthorizationHeader(cookieAuthdata);
        }


        function buildParams(paramsObject)
        {
            var r20 = /%20/g, paramsArray = [];
            angular.forEach(paramsObject, function (value, key)
            {
                paramsArray[ paramsArray.length ] = encodeURIComponent(key) + '=' + encodeURIComponent(value);
            });
            return paramsArray.join('&').replace(r20, '+');
        }

        var authenticator = {
            login: function (email, password, success, failure)
            {
                var payload = buildParams({username: email, password: password});
                var config = {
                    headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
                };
                //delete auth header & cookie
                delete $http.defaults.headers.common.Authorization;
                $window.$.removeCookie('token', {path: $window.clientContextPath});

                var request = $http.post($window.doubleEscapedContextPath + '/api/user/auth', payload, config).success(function (data)
                {
                    authenticator.setToken(data);
                    if (success instanceof Function) {
                        success();
                    }
                });
                if (failure instanceof Function) {
                    request.error(failure);
                }
            },
            logout: function ()
            {
                document.execCommand('ClearAuthenticationCache');
                $window.$.removeCookie('token', {path: $window.clientContextPath});
                delete $http.defaults.headers.common.Authorization;
            },
            setToken: function (token)
            {
                if (null == token) {
                    throw new Error(gettextCatalog.getString('Token may not be null or undefined'));
                }

                // Cookie expires next day 03:00:00 AM
                var result = new Date();
                result.setDate(result.getDate() + 1);
                result.setHours(3);
                result.setMinutes(0);
                result.setSeconds(0);

                $window.$.cookie('token', token, {path: $window.clientContextPath, expires: result});
                setupAuthorizationHeader(token);
                //try to fetch current user if token is set
                $rootScope.$broadcast('RestBase:authentication-token-set');
            }
        };
        return  authenticator;
    }

    function Base64(gettextCatalog)
    {
        var keyStr = 'ABCDEFGHIJKLMNOP' + 'QRSTUVWXYZabcdef' + 'ghijklmnopqrstuv' + 'wxyz0123456789+/' + '=';
        //noinspection JSUnusedGlobalSymbols
        return {
            encode: function (input)
            {
                var output = '';
                var chr1, chr2, chr3 = '';
                var enc1, enc2, enc3, enc4 = '';
                var i = 0;

                do {
                    chr1 = input.charCodeAt(i++);
                    chr2 = input.charCodeAt(i++);
                    chr3 = input.charCodeAt(i++);
                    /*jshint bitwise:false*/
                    enc1 = chr1 >> 2;
                    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                    enc4 = chr3 & 63;

                    if (isNaN(chr2)) {
                        enc3 = enc4 = 64;
                    } else if (isNaN(chr3)) {
                        enc4 = 64;
                    }

                    //noinspection JSValidateTypes
                    output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
                    chr1 = chr2 = chr3 = '';
                    enc1 = enc2 = enc3 = enc4 = '';
                } while (i < input.length);

                return output;
            },

            decode: function (input)
            {
                var output = '';
                var chr1, chr2, chr3 = '';
                var enc1, enc2, enc3, enc4 = '';
                var i = 0;

                // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
                var base64test = /[^A-Za-z0-9\+\/=]/g;
                if (base64test.exec(input)) {
                    throw new Error(gettextCatalog.getString('There were invalid base64 characters in the input text.\n' +
                            'Valid base64 characters are A-Z, a-z, 0-9, "+", "/",and "="\n' + 'Expect errors in decoding.'));
                }
                //noinspection JSCheckFunctionSignatures
                input = input.replace(/[^A-Za-z0-9\+\/=]/g, '');

                do {
                    enc1 = keyStr.indexOf(input.charAt(i++));
                    enc2 = keyStr.indexOf(input.charAt(i++));
                    enc3 = keyStr.indexOf(input.charAt(i++));
                    enc4 = keyStr.indexOf(input.charAt(i++));

                    /*jshint bitwise:false*/
                    chr1 = (enc1 << 2) | (enc2 >> 4);
                    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                    chr3 = ((enc3 & 3) << 6) | enc4;

                    output = output + String.fromCharCode(chr1);

                    if (enc3 !== 64) {
                        output = output + String.fromCharCode(chr2);
                    }
                    if (enc4 !== 64) {
                        //noinspection JSValidateTypes
                        output = output + String.fromCharCode(chr3);
                    }

                    chr1 = chr2 = chr3 = '';
                    enc1 = enc2 = enc3 = enc4 = '';

                } while (i < input.length);

                return output;
            }
        };
    }

    /**
     * Authenticator must be in different module than ExceptionHandler.
     */
    var module = angular.module('itc.security');
    //noinspection JSValidateTypes
    module.factory('Authenticator', ['$http', '$rootScope', '$window', 'authService', 'Base64', 'gettextCatalog', Authenticator]);
    module.factory('Base64', ['gettextCatalog', Base64]);
})();
