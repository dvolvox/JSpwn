var scanjsModule = angular.module('scanjs', ['ui.bootstrap', 'ngRoute']);

scanjsModule.config(['$routeProvider',
  function($routeProvider) {
    $routeProvider.
      when('/scan', {
        templateUrl: 'partials/scan.html',
        controller: 'ScanCtrl'
      }).
      when('/rules', {
        templateUrl: 'partials/rules.html',
        controller: 'RuleListCtrl'
      }).
      when('/experiment', {
        templateUrl: 'partials/experiment.html',
        controller: 'ExperimentCtrl'
      }).
      when('/coderoad', {
        templateUrl: 'partials/coderoad.html',
        controller: 'coderoadctrl'
      }).
      otherwise({
        redirectTo: '/scan/client'
      });
  }]);
