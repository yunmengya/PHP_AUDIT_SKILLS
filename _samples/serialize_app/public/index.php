<?php
$u = $_GET['u'] ?? '';
unserialize($u);

$y = $_GET['y'] ?? '';
yaml_parse($y);

$z = $_GET['z'] ?? '';
igbinary_unserialize($z);
