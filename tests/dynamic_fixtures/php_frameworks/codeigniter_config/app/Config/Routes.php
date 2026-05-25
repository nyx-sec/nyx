<?php
use CodeIgniter\Router\RouteCollection;

$routes->get('users/(:num)', 'UserController::show');
