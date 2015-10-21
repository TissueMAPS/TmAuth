(function (angular) {

  // Create all modules and define dependencies to make sure they exist
  // and are loaded in the correct order to satisfy dependency injection
  // before all nested files are concatenated by Gulp

  // Config
  angular.module('tmauth.config', [])
      .value('tmauth.config', {
          debug: true
    });

  // Modules
  angular.module('tmauth.directives', [
      'tmauth.controllers'
  ]);
  angular.module('tmauth.constants', []);
  angular.module('tmauth.filters', []);
  angular.module('tmauth.services', [
      'tmauth.constants'
  ]);
  angular.module('tmauth.controllers', [
      'tmauth.services'
  ]);
  angular.module('tmauth',
      [
          'ui.bootstrap',

          'tmauth.config',
          'tmauth.directives',
          'tmauth.constants',
          'tmauth.filters',
          'tmauth.services'
      ]);

})(angular);

angular.module('tmauth.constants')
.constant('AUTH_EVENTS', {
    loginSuccess: 'auth-login-success',
    loginFailed: 'auth-login-failed',
    logoutSuccess: 'auth-logout-success',
    sessionTimeout: 'auth-session-timeout',
    notAuthenticated: 'auth-not-authenticated',
    notAuthorized: 'auth-not-authorized'
});

angular.module('tmauth.constants')
.constant('USER_ROLES', {
    all: '*',
    admin: 'admin',
    user: 'user',
    guest: 'guest'
});

angular.module('tmauth.directives')
.directive('tmInlineLoginForm', function() {

    var template =
        '<form class="tm-inline-login-form navbar-form navbar-right"' +
              'ng-submit="auth.login()"' +
              'ng-hide="auth.isAlreadyLoggedIn()">' +
          '<div class="form-group">' +
            '<input type="text" placeholder="username" class="form-control"' +
                   'ng-model="auth.form.username">' +
          '</div>' +
          '<div class="form-group">' +
            '<input type="password" placeholder="password" class="form-control"' +
                   'ng-model="auth.form.password">' +
          '</div>' +
          '<button type="submit" class="btn btn-success">Sign in</button>' +
        '</form>';

    return {
        template: template,
        restrict: 'E',
        controller: 'LoginCtrl',
        controllerAs: 'auth'
    };

});

angular.module('tmauth.controllers')
.controller('LoginCtrl', ['$scope', '$rootScope', 'authService',
            function($scope, $rootScope, authService) {

    var self = this;

    this.form = {
        username: undefined,
        password: undefined
    };

    this.isAlreadyLoggedIn = function() {
        return authService.isAuthenticated();
    };

    this.login = function() {
        authService.login(self.form.username, self.form.password);
    };
}]);

angular.module('tmauth.controllers')
.controller('LoginDialogCtrl', ['authService', '$rootScope', '$scope',
            function(authService, $rootScope, $scope) {

    this.form = {
        username: undefined,
        password: undefined
    };

    this.login = function(username, password) {
        authService.login(username, password)
        .then(function(user) {
            // Login was OK, return the current user object to the caller
            $scope.$close(user);
        });
    };
}]);

angular.module('tmauth.services')
// TODO: Add additional information such as first name, last name, etc.
.factory('User', ['USER_ROLES', function(USER_ROLES) {
    function User(id, name, roles) {
        this.id = id;
        this.name = name;
        this.roles = roles;
    }

    User.prototype.isAdmin = function() {
        return _(this.roles).contains(USER_ROLES.admin);
    };

    return User;
}]);

angular.module('tmauth.services')
.factory('authInterceptor', ['$q', '$window', function($q, $window) {

    function request(config) {
        config.headers = config.headers || {};
        var token = $window.sessionStorage.token;
        if (angular.isDefined(token)) {
            config.headers.Authorization = 'Bearer ' + token;
        }
        return config;
    }

    function response(resp) {
        if (resp.status === 401) {
            // handle case when user is not authenticated
            console.log('User not authenticated!');
        }
        return resp || $q.when(resp);
    }

    return {
        request: request,
        response: response
    };

}]);

angular.module('tmauth.services')
.service('authService', ['$http', 'session', 'User', '$rootScope', 'AUTH_EVENTS',
         function($http, session, User, $rootScope, AUTH_EVENTS) {

    /**
     * Ask the server to check if there is a username with a given
     * username/password combination. If there is, the server will return a
     * token which can be used to authenticate subsequent requests.
     * The token will be stored in sessionStorage where it is retrieved on every
     * request by a middleware (authInterceptor).
     */
    this.login = function(username, password) {
        var credentials = {
            username: username,
            password: password
        };
        return $http
        .post('/auth', credentials)
        .success(function(data, status) {
            var token = data.access_token;
            // TODO: sessionStorage not supported in all browsers,
            // include polyfill to make it supported.
            var user = session.create(token);

            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);

            return user;
        })
        .error(function(data, status) {
            session.destroy();
            $rootScope.$broadcast(AUTH_EVENTS.loginFailed);
        });
    };

    this.logout = function() {
        session.destroy();
        $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
    };

    /**
     * Check if the current user is logged in.
     */
    this.isAuthenticated = function () {
        var isAuth = session.isAuth();
        return isAuth;
    };

    /**
     * Check if the current user has authorization for performing tasks
     * that are available to the roles in `authorizedRoles`.
     */
    this.isAuthorized = function(authorizedRoles) {
        if (!angular.isArray(authorizedRoles)) {
            authorizedRoles = [authorizedRoles];
        }

        var hasUserMatchingRole = _(session.user.roles).map(function(role) {
            return _(authorizedRoles).contains(role);
        });

        return this.isAuthenticated() && _.some(hasUserMatchingRole);
    };
}]);

angular.module('tmauth.services')
.factory('jwtUtil', ['$window', function($window) {

    function decodeToken(token) {
        var parts = token.split('.');
        var headerBase64 = parts[0];
        var payloadBase64 = parts[1];

        function decode(partBase64) {
            partBase64 = partBase64.replace('-', '+').replace('_', '/');
            return JSON.parse($window.atob(partBase64));
        }

        return {
            header: decode(headerBase64),
            payload: decode(payloadBase64)
        };
    }

    function isTokenExpired(token) {
        var decoded = decodeToken(token);
        var exp = decoded.payload.exp;
        var d = new Date(0);
        d.setUTCSeconds(exp);
        return !(d.valueOf() > new Date().valueOf());
    }

    return {
        decodeToken: decodeToken,
        isTokenExpired: isTokenExpired
    };
}]);

angular.module('tmauth.services')
.service('loginDialogService', ['$modal', '$rootScope', function($modal, $rootScope) {

    this.showDialog = function() {

        var instance = $modal.open({
            templateUrl: '/templates/main/auth/login-dialog.html',
            controller: 'LoginDialogCtrl',
            controllerAs: 'login'
        });

        return instance.result;

    };

}]);

angular.module('tmauth.services')
.service('session',
         ['$window', 'jwtUtil', 'User', '$interval',
            function($window, jwtUtil, User, $interval) {

    var user = null;

    var tokenValid = false;

    /**
     * Start to check the token every `milliseconds` for invaliditity.
     * This function will only set tokenValid to false, never to true!
     */
    var intervalPromise = undefined;

    function startCheckingToken(milliseconds) {
        function checkIfTokenIsValid() {
            var token = $window.sessionStorage.token;
            var tokenExists = !_.isUndefined(token);

            if (!tokenExists) {
                tokenValid = false;
            } else {
                var tokenExpired = jwtUtil.isTokenExpired(token);
                var userLoggedIn = !!user;

                if (tokenExpired) { console.log('Token expired'); }

                if (tokenExpired || !userLoggedIn) {
                    tokenValid = false;
                }
            }
        }

        $interval(checkIfTokenIsValid, milliseconds);
    }

    function stopCheckingToken() {
        $interval.cancel(intervalPromise);
    }

    function setTokenValid() {
        tokenValid = true;
        startCheckingToken(1000);
    }

    function setTokenInvalid() {
        stopCheckingToken();
        tokenValid = false;
    }

    /**
     * Check if there is still a token in the sessionStorage.
     * Maybe the page was reloaded but the token is still there.
     */
    var token = $window.sessionStorage.token;
    if (angular.isDefined(token) && !jwtUtil.isTokenExpired(token)) {
        console.log('Restoring session from existing token...');
        var tokenDecoded = jwtUtil.decodeToken(token);
        var payload = tokenDecoded.payload;
        user = new User(payload.uid, payload.uname, payload.uroles);

        setTokenValid();
    }

    this.create = function(token) {
        var tokenDec = jwtUtil.decodeToken(token);
        var payload = tokenDec.payload;
        var header = tokenDec.header;
        user = new User(payload.uid, payload.uname, payload.uroles);
        $window.sessionStorage.token = token;

        setTokenValid();

        return user;
    };

    this.destroy = function() {
        delete $window.sessionStorage.token;
        user = null;

        setTokenInvalid();
    };

    this.getUser = function() {
        return user;
    };

    this.isAuth = function() {
        return tokenValid;
    };

}]);
