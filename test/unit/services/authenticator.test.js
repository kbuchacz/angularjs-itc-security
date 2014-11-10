/*jshint camelcase:false*/
describe('Authenticator', function ()
{
    'use strict';

    beforeEach(module('itc.security'));

    beforeEach(inject(function ($window)
    {
        $window.$ = {
            cookie: jasmine.createSpy('$.cookie'),
            removeCookie: jasmine.createSpy('$.removeCookie')
        };
        $window.doubleEscapedContextPath = '/someContextPath';
        $window.clientContextPath = '/';
    }));

    describe('constructor', function ()
    {
        describe('when token set in cookie', function ()
        {
            beforeEach(inject(function ($window)
            {
                $window.$.cookie.andReturn('a');
            }));
            it('should set authorization header', inject(function (Authenticator, $http)
            {
                expect($http.defaults.headers.common.Authorization).toBe('Token YQ==');
            }));
        });
    });


    describe('login', function ()
    {
        describe('when error callback defined', function ()
        {
            describe('when http responds with 401', function ()
            {
                var errorCallback;
                beforeEach(inject(function ($httpBackend, $window, Authenticator)
                {
//                Given
                    errorCallback = jasmine.createSpy('errorCallback');
                    //noinspection JSValidateTypes
                    $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(401);
//                When
                    Authenticator.login('a', 'a', null, errorCallback);
                    $httpBackend.flush();
                }));
                it('should invoke error callback', function ()
                {

                    expect(errorCallback).toHaveBeenCalled();
                });
            });
            describe('when http responds with code 4xx different than 401', function ()
            {
                var errorCallback;
                beforeEach(inject(function ($httpBackend, $window, Authenticator)
                {
//                Given
                    errorCallback = jasmine.createSpy('errorCallback');
                    //noinspection JSValidateTypes
                    $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(405);

//                When
                    Authenticator.login('a', 'a', null, errorCallback);
                    $httpBackend.flush();
                }));
                it('should invoke error callback', function ()
                {
                    expect(errorCallback).toHaveBeenCalled();
                });
            });
        });
        describe('when error callback is undefined', function ()
        {
            describe('when http responds with 401', function ()
            {
                beforeEach(inject(function ($httpBackend, $window, Authenticator)
                {
//                Given
                    //noinspection JSValidateTypes
                    $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(401);

//                When
                    Authenticator.login('a', 'a', null, null);
                    $httpBackend.flush();
                }));
                it('should NOT invoke error callback', function ()
                {
//                    Just let's see if ther is no exception
                });
            });
            describe('when http responds with code 4xx different than 401', function ()
            {
                beforeEach(inject(function ($httpBackend, $window, Authenticator)
                {
//                Given
                    //noinspection JSValidateTypes
                    $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(405);

//                When
                    Authenticator.login('a', 'a', null, null);
                    $httpBackend.flush();
                }));
                it('should invoke error callback', function ()
                {
//                    Just let's see if ther is no exception
                });
            });
        });
        describe('when already logged in', function ()
        {
            var callback, authenticationTokenSetListener;
            beforeEach(inject(function ($httpBackend, $http, $rootScope, $window, Authenticator)
            {
                $window.$.cookie.andReturn('a');
                $http.defaults.headers.common.Authorization = 'b';
                authenticationTokenSetListener = jasmine.createSpy('authenticationTokenSetListener');
                callback = jasmine.createSpy('successCallback');
                $rootScope.$on('RestBase:authentication-token-set', authenticationTokenSetListener);
                //noinspection JSCheckFunctionSignatures
                $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(200, 'c');
//                When
                Authenticator.login('a', 'a', callback);
                $httpBackend.flush();
            }));
            it('should override authorization header', inject(function ($http)
            {
                expect($http.defaults.headers.common.Authorization).toBe('Token Yw==');
            }));
            it('should override cookie', inject(function ($window)
            {
                expect($window.$.cookie).toHaveBeenCalledWith('token');
                expect($window.$.cookie).toHaveBeenCalledWith('token', 'c', {path: '/', expires: jasmine.any(Date)});
                expect($window.$.cookie.calls.length).toBe(2);
            }));
            it('should raise event', function ()
            {
                expect(authenticationTokenSetListener).toHaveBeenCalled();
                expect(authenticationTokenSetListener.calls.length).toBe(1);
            });
            it('should invoke success callback', function ()
            {
                expect(callback).toHaveBeenCalled();
                expect(callback.calls.length).toBe(1);
            });
        });
        describe('when success', function ()
        {
            var callback, $httpBackend, authenticationTokenSetListener;
            beforeEach(inject(function (_$httpBackend_, $http, $rootScope, $window, Authenticator)
            {
//                Given
                authenticationTokenSetListener = jasmine.createSpy('authenticationTokenSetListener');
                $rootScope.$on('RestBase:authentication-token-set', authenticationTokenSetListener);
                delete $http.defaults.headers.common.Authorization;
                $httpBackend = _$httpBackend_;
                callback = jasmine.createSpy('successCallback');
                //noinspection JSCheckFunctionSignatures
                $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(200, 'a');
//                When
                Authenticator.login('a', 'a', callback);
                $httpBackend.flush();
            }));

            it('should send proper request to the backend', function ()
            {
                $httpBackend.verifyNoOutstandingExpectation();
            });
            it('should set authorization header', inject(function ($http)
            {
                expect($http.defaults.headers.common.Authorization).toBe('Token YQ==');
            }));
            it('should set cookie', inject(function ($window)
            {
                expect($window.$.cookie).toHaveBeenCalledWith('token');
                expect($window.$.cookie).toHaveBeenCalledWith('token', 'a', {path: '/', expires: jasmine.any(Date)});
                expect($window.$.cookie.calls.length).toBe(2);
            }));
            it('should raise event', function ()
            {
                expect(authenticationTokenSetListener).toHaveBeenCalled();
                expect(authenticationTokenSetListener.calls.length).toBe(1);
            });
        });

        describe('when success and success callback is function', function ()
        {
            var callback;
            beforeEach(inject(function ($httpBackend, $window, Authenticator)
            {
                //                Given
                callback = jasmine.createSpy('successCallback');
                //noinspection JSCheckFunctionSignatures
                $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(200, 'a');
                //                When
                Authenticator.login('a', 'a', callback);
                $httpBackend.flush();
            }));
            it('should invoke success callback', function ()
            {
                expect(callback).toHaveBeenCalled();
                expect(callback.calls.length).toBe(1);
            });
        });

        describe('when success and success callback is NOT a function', function ()
        {
            var callback;
            beforeEach(inject(function ($httpBackend, $window, Authenticator)
            {
                //                Given
                callback = {};
                //noinspection JSCheckFunctionSignatures
                $httpBackend.expectPOST($window.doubleEscapedContextPath + '/api/user/auth').respond(200, 'a');
                //                When
                Authenticator.login('a', 'a', callback);
                $httpBackend.flush();
            }));
            it('should NOT invoke success callback', function ()
            {
//                Just let's see if ther is no exception
            });
        });

    });
    describe('logout', function ()
    {
        describe('when loged in', function ()
        {
            beforeEach(inject(function ($http, Authenticator)
            {
                $http.defaults.headers.common.Authorization = 'a';
                Authenticator.logout();
            }));
            it('should clear authorization header', inject(function ($http)
            {
                expect($http.defaults.headers.common.Authorization).toBeUndefined();
            }));
            it('should remove cookie', inject(function ($window)
            {
                expect($window.$.removeCookie).toHaveBeenCalled();
                expect($window.$.removeCookie.calls.length).toBe(1);
            }));
        });

        describe('when NOT logged in', function ()
        {
            beforeEach(inject(function ($http, Authenticator)
            {
                delete $http.defaults.headers.common.Authorization;
                Authenticator.logout();
            }));
            it('should clear authorization header', inject(function ($http)
            {
                expect($http.defaults.headers.common.Authorization).toBeUndefined();
            }));
            it('should remove cookie', inject(function ($window)
            {
                expect($window.$.removeCookie).toHaveBeenCalled();
                expect($window.$.removeCookie.calls.length).toBe(1);
            }));
        });
    });
    describe('setToken', function ()
    {
        describe('when token is empty', function ()
        {
            describe('undefined', function ()
            {
                it('should throw Error', inject(function (Authenticator)
                {
                    expect(angular.bind(Authenticator, Authenticator.setToken, undefined)).toThrow('Token may not be null or undefined');
                }));
            });
            describe('null', function ()
            {
                it('should throw Error', inject(function (Authenticator)
                {
                    expect(angular.bind(Authenticator, Authenticator.setToken, null)).toThrow('Token may not be null or undefined');
                }));
            });

        });
        describe('when token is NOT empty', function ()
        {
            var authenticationTokenSetListener;
            beforeEach(inject(function ($http, $rootScope, Authenticator)
            {
                delete $http.defaults.headers.common.Authorization;
                authenticationTokenSetListener = jasmine.createSpy('authenticationTokenSetListener');
                $rootScope.$on('RestBase:authentication-token-set', authenticationTokenSetListener);
//                When
                Authenticator.setToken('a');
            }));

            it('should set authorization header', inject(function ($http)
            {
                expect($http.defaults.headers.common.Authorization).toBe('Token YQ==');
            }));
            it('should set cookie', inject(function ($window)
            {
                expect($window.$.cookie).toHaveBeenCalledWith('token');
                expect($window.$.cookie).toHaveBeenCalledWith('token', 'a', {path: '/', expires: jasmine.any(Date)});
                expect($window.$.cookie.calls.length).toBe(2);
            }));
            it('should raise event', function ()
            {
                expect(authenticationTokenSetListener).toHaveBeenCalled();
                expect(authenticationTokenSetListener.calls.length).toBe(1);
            });
        });
    });
});


describe('Base64', function ()
{
    'use strict';

    beforeEach(module('itc.security'));

    describe('encode', function ()
    {
        it('should properly encode', inject(function (Base64)
        {
            expect(Base64.encode('a')).toBe('YQ==');
            expect(Base64.encode('a2')).toBe('YTI=');
            expect(Base64.encode('a22')).toBe('YTIy');
            expect(Base64.encode('abra kadabra')).toBe('YWJyYSBrYWRhYnJh');
            expect(Base64.encode('line\nwith new line\n')).toBe('bGluZQp3aXRoIG5ldyBsaW5lCg==');
        }));
    });
    describe('decode', function ()
    {
        it('should properly decode', inject(function (Base64)
        {
            expect(Base64.decode('YQ==')).toBe('a');
            expect(Base64.decode('YWJyYSBrYWRhYnJh')).toBe('abra kadabra');
            expect(Base64.decode('bGluZQp3aXRoIG5ldyBsaW5lCg==')).toBe('line\nwith new line\n');
        }));

        describe('when input contains invalid characters', function ()
        {
            it('should throw Error', inject(function (Base64)
            {
                expect(angular.bind(Base64, Base64.decode, '*')).toThrow('There were invalid base64 characters in the input text.\n' +
                        'Valid base64 characters are A-Z, a-z, 0-9, "+", "/",and "="\n' + 'Expect errors in decoding.');
            }));
        });
    });
});
