#!/usr/bin/php
<?php
  error_reporting(E_ALL);
  $zone = trim(file_get_contents("/etc/timezone"));
  date_default_timezone_set($zone);
  $date = date("D, d M o H:i:s O");
  $version = $argv[1];
?>
plcultima (<?= $version ?>) none; urgency=low

  * Daily build

 -- PLCU Group AG <noreply@plc-group.ag>  <?= $date ?>
