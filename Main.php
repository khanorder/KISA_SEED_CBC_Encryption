<?php
require_once ('KISA_SEED_CBC_HANDLE.php');

$handle = new KISA_SEED_CBC_HANDLE();
$PlanText = "KISA SEED 암호화 알고리즘 테스트 문자열 " . date("Y-m-d");
$ChiperText = $handle->encrypt($PlanText);
echo "암호화 : " . $ChiperText . PHP_EOL;
$DecryptText = $handle->decrypt(trim($ChiperText));
echo "복호화 : " . $DecryptText . PHP_EOL;