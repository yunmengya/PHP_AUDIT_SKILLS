<?php
$u = $_GET['u'] ?? '';
$ch = curl_init($u);

$u2 = $_GET['u2'] ?? '';
$ch2 = curl_init($u2);

$xml = $_POST['xml'] ?? '';
simplexml_load_string($xml);
