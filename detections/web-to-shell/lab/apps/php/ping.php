<?php
// LAB ONLY: deliberately vulnerable to OS command injection.
// Try: /ping.php?host=127.0.0.1;id
$host = $_GET['host'] ?? '127.0.0.1';
header('Content-Type: text/plain');
system('ping -c 1 -W 1 ' . $host);
