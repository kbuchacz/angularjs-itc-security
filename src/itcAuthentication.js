/*global clientContextPath*/
(function ()
{
    'use strict';

    function itcAuthentication($http, $timeout)
    {
        return {
            restrict: 'C',
            link: function (scope, elem)
            {
                var login = elem.find('#login-holder');

                /**
                 * Since Angular 1.2-rc3 ng-view element is not in DOM at the time of executing this linking function
                 */
                function getRequredElements()
                {
                    return elem.find('.authentication-required');
                }

                login.hide();

                scope.$on('event:auth-loginRequired', function ()
                {
                    //clear cookie & auth header, when login required event is raised
                    $.removeCookie('token', {path: clientContextPath});
                    delete $http.defaults.headers.common.Authorization;

                    if (true !== scope.$root.isLoginView) {
                        getRequredElements().hide();
                        login.show();
                        login.find('#inputUsername').focus();
                    }
                });

                scope.$on('event:signupRequired', function ()
                {
                    getRequredElements().hide();
                    login.show();
                    $timeout(function ()
                    {
                        login.find('#inputEmail2').focus();
                    });
                });

                scope.$on('event:startChangeForgottenPassword', function ()
                {
                    getRequredElements().hide();
                    login.show();
                    $timeout(function ()
                    {
                        login.find('#inputEmailForRemindPass').focus();
                    });
                });

                var hide = function ()
                {
                    getRequredElements().show();
                    login.slideUp();
                };
                scope.$on('event:auth-loginConfirmed', hide);
                scope.$on('event:hide-signup', hide);
            }
        };
    }

    //noinspection JSValidateTypes
    /**
     * This directive is responsible for showing/hiding login form.
     */
    angular.module('itc.security').directive('itcAuthentication', ['$http', '$timeout', itcAuthentication]);
})();
