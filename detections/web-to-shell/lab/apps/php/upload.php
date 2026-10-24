<?php
// LAB ONLY: deliberately accepts any file type, including .php (webshell drop).
// Try: curl -F file=@note.php http://victim/upload.php
header('Content-Type: text/plain');
if (!isset($_FILES['file'])) {
    http_response_code(400);
    exit("POST a file field named 'file'\n");
}
$name = basename($_FILES['file']['name']);
move_uploaded_file($_FILES['file']['tmp_name'], __DIR__ . '/uploads/' . $name);
echo "/uploads/$name\n";
