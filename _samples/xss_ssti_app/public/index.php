<?php
$q = $_GET['q'] ?? '';
echo $q;

$p = $_GET['p'] ?? '';
print $p;

$tpl = $_GET['tpl'] ?? '';
$twig->render($tpl);
