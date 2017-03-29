<?php

$url = "http://localhost/scan";

$username = "app1";
$password = "letmein";
$filename = getcwd() . "/eicar.txt";

$file = fopen($filename, "rb");
$filedata = fread($file, filesize($filename));

$file = new CURLFile($filename);
$file->setPostFilename($filename);

$headers = array("Content-Type:multipart/form-data");
$postfields = array("filedata" => $file, "filename" => $filename);

$ch = curl_init();

curl_setopt($ch, CURLOPT_USERPWD, $username . ":" . $password);

$options = array(
    CURLOPT_URL => $url,
    CURLOPT_POST => 1,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_POSTFIELDS => $postfields,
    CURLOPT_INFILESIZE => $filesize,
    CURLOPT_RETURNTRANSFER => true
);

curl_setopt_array($ch, $options);

$response = curl_exec($ch);

echo($response);

curl_close($ch);


