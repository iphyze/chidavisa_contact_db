<?php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo json_encode(["message" => "Welcome to AAR Global Database API 😊"]);
    exit;
}else{
    echo json_encode(["message" => "Not found!"]);
    http_response_code(404);
    exit;
}
?>
