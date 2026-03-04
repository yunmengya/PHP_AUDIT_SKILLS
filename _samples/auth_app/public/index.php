<?php
$router->get('/u', 'UserController@view');
$router->post('/u/update', 'UserController@update');
$router->delete('/u/delete', 'UserController@delete');
