#!/usr/bin/php
<?php

# INWX certbot2 auth hook handler
# Christoph Ender
# 2024-06-07
# https://github.com/chrender/certbot2-inwx-handler.git
# https://it-sys-ce.de


# ---
# This script may be used for certbot2's "--manual-auth-hook" handler.
# You'll have to set the following parameters, for example via "export"
# before invoking certbot, to make things work:
# - CERTBOT_INWX_USERNAME: The inwx username
# - CERTBOT_INWX_PASSWORD: Your inwx password
# - CERTBOT_INWX_MFATOKEN: Your inwx google auth token

# --- These are automatically set by certbot2:
# CERTBOT_DOMAIN: The domain being authenticated
# CERTBOT_VALIDATION: The validation string


$logFileHandle = NULL;
error_reporting(E_ALL);
require 'vendor/autoload.php';


# Cleanup on exit
function onDie() {
  global $logFileHandle;
  if (!is_null($logFileHandle)) {
    logToFile("Exiting " . basename(__FILE__) . ".");
    fclose($logFileHandle);
  }
}
register_shutdown_function('onDie');


# Loggig function
function logToFile($output) {
  global $logFileHandle;
  $now = DateTime::createFromFormat('U.u', microtime(true));
  $timestamp = $now->format("m-d-Y H:i:s.u");
  print("[" . $timestamp . "] " . $output . "\n");
  fwrite($logFileHandle, "[" . $timestamp . "] " . $output . "\n");
}


# Login to INWX
function login() {
  global $certbot_inwx_username, $certbot_inwx_password,
    $certbot_inwx_mfatoken;

  $domrobot = new \INWX\Domrobot();

  logToFile("Starting login.");

  $result = $domrobot->setLanguage('en')
    ->useJson()
    ->useLive() // ->useOte()
    ->setDebug(true)
    ->login($certbot_inwx_username,
            $certbot_inwx_password,
            $certbot_inwx_mfatoken);

  logToFile("--- Login result ---");
  logToFile(print_r($result));
  logToFile("--------------------");

  if ($result['code'] != 1000) {
    exit -1;
  }

  return $domrobot;
}


# Logout from INWX
function logout($domrobot) {
  logToFile("Logging out.");
  $domrobot->logout();
}


# Split domain name
function getLeftAndRightSide($domain) {
  $domainParts = explode('.', $domain);
  $domainPartCount = count($domainParts);
  $leftSide = "";
  $i=0;
  while ($i < $domainPartCount - 2) {
    if (strlen($leftSide) > 0) { $leftSide .= "."; }
    $leftSide .= $domainParts[$i];
    $i++;
  }
  $rightSide
    = $domainParts[$domainPartCount - 2] . "."
    . $domainParts[$domainPartCount - 1];

  logToFile("Left side: \"" . $leftSide . "\".");
  logToFile("Right side: \"" . $rightSide . "\".");

  return [ 'leftSide' => $leftSide, 'rightSide' => $rightSide ];
}


$logFilename = dirname(__FILE__) . "/logs/" . date("Y-m-d-H-i-s") . ".txt";
$logFileHandle = fopen($logFilename, "w");
logToFile("Starting " . basename(__FILE__) . ".");

$certbot_inwx_username = getenv('CERTBOT_INWX_USERNAME');
$certbot_inwx_password = getenv('CERTBOT_INWX_PASSWORD');
$certbot_inwx_mfatoken = getenv('CERTBOT_INWX_MFATOKEN');
$certbot_validation = getenv('CERTBOT_VALIDATION');
$certbot_domain = getenv('CERTBOT_DOMAIN');

logToFile("Using username \"" . $certbot_inwx_username . "\".");
logToFile("Length of password: " . strlen($certbot_inwx_password) . ".");
logToFile("Length of mfa-token: " . strlen($certbot_inwx_mfatoken) . ".");
logToFile("Validation string: " . $certbot_validation . ".");
logToFile("Domain: " . getenv("CERTBOT_DOMAIN") . ".");

$certbot_domain = "_acme-challenge.${certbot_domain}".
$bothSides = getLeftAndRightSide($certbot_domain);
$domrobot = login();
$result = $domrobot->call(
  'nameserver', 'createRecord',
  [ 'domain' => $bothSides['rightSide'],
    'type' => 'TXT',
    'name' => $bothSides['leftSide'],
    'content' => $certbot_validation,
    'ttl' => 300,
    'testing' => false ]);

if ($result['code'] == 1000) {
  $resData = $result['resData'];
  $recordId = $resData['id'];
}
logout($domrobot);

sleep(30);
?>

