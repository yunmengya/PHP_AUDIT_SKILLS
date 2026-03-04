<?php
$p = $_GET['p'] ?? '';
file_get_contents($p);

$f = $_GET['f'] ?? '';
file_put_contents($f, "x");

$i = $_GET['i'] ?? '';
include $i;
