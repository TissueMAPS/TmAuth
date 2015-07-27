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
  angular.module('tmauth.directives', []);
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
