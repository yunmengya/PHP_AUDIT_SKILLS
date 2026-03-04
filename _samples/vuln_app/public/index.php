<?php
$id = $_GET['id'] ?? '';
$sql = "SELECT * FROM users WHERE id=" . $id;
$db->query($sql);

$cmd = $_GET['cmd'] ?? '';
system($cmd);

$path = $_GET['p'] ?? '';
file_get_contents($path);

$url = $_GET['url'] ?? '';
$ch = curl_init($url);

$xml = $_POST['xml'] ?? '';
simplexml_load_string($xml);

$q = $_GET['q'] ?? '';
echo $q;

$u = $_GET['u'] ?? '';
unserialize($u);
