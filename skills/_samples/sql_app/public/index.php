<?php
$id = $_GET['id'] ?? '';
$sql = "SELECT * FROM users WHERE id=" . $id;
$db->query($sql);

$name = $_GET['name'] ?? '';
mysqli_query($conn, "SELECT * FROM users WHERE name='" . $name . "'");

$uid = $_GET['uid'] ?? '';
$pdo->query("SELECT * FROM users WHERE uid=" . $uid);
