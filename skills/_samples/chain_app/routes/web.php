<?php
use Illuminate\Support\Facades\Route;

Route::get('/admin', 'AdminController@index');
Route::get('/user', 'UserController@show');
