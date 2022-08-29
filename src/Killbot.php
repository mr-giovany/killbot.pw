<?php

namespace Kgsdev;

use GuzzleHttp\Client;

abstract class Killbot
{
  public Client $client;

  public function __construct()
  {
    $this->client = new Client(['http_errors' => false]);
  }

  /**
   * apiKey
   * @return string
   */
  abstract public function apiKey();

  /**
   * botRedirect
   *
   * @return string
   */
  abstract public function botRedirect();

  /**
   * whiteLists
   *
   * @return array
   */
  abstract public function whiteLists();

  /**
   * logsFile
   *
   * @return string
   */
  abstract public function logsFile();

  public function writeLog(array $infos)
  {
    file_put_contents($this->logsFile(), $this->ipv4() . ' | ' . implode(' | ', $infos) . PHP_EOL, FILE_APPEND);
  }

  public function ipv4()
  {
    $ipaddress = '';

    if (getenv('HTTP_CLIENT_IP')) {
      $ipaddress = getenv('HTTP_CLIENT_IP');
    }

    if (getenv('HTTP_X_FORWARDED_FOR')) {
      $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
    }

    if (getenv('HTTP_X_FORWARDED')) {
      $ipaddress = getenv('HTTP_X_FORWARDED');
    }

    if (getenv('HTTP_FORWARDED_FOR')) {
      $ipaddress = getenv('HTTP_FORWARDED_FOR');
    }

    if (getenv('HTTP_FORWARDED')) {
      $ipaddress = getenv('HTTP_FORWARDED');
    }

    if (getenv('REMOTE_ADDR')) {
      $ipaddress = getenv('REMOTE_ADDR');
    }

    $ipaddress = explode(",",  $ipaddress);

    if (preg_match("/::1/", $ipaddress[0])) {
      $ipaddress[0] = '8.8.8.8';
    }

    if ($ipaddress[0] == '127.0.0.1') {
      $ipaddress[0] = '120.188.74.35';
    }

    return $ipaddress[0];
  }

  public function currentURL()
  {
    return (((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://") . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
  }

  public function checkBot()
  {
    return json_decode(
      $this->client->get('https://killbot.org/api/v2/blocker?' . http_build_query([
        'ip'      =>  $this->ipv4(),
        'apikey'  =>  $this->apiKey(),
        'ua'      =>  urlencode($_SERVER['HTTP_USER_AGENT']),
        'url'     =>  urlencode($_SERVER['REQUEST_URI'])
      ]))->getBody()->getContents()
    );
  }

  public function allows()
  {
    header('HTTP/1.0 307 Temporary Redirect');
    die('<script>window.location = "' . $this->botRedirect() . '";</script>');
  }

  public function runBlocker()
  {
    $botApiResponse = $this->checkBot();
    $botStatus = optional($botApiResponse);
    $selectedInfos = collect($botApiResponse->data)->only([
      'block_by',
      'info.user_agent',
      'info.ipinfo.region',
      'info.ipinfo.city',
      'info.ipinfo.country',
      'info.ipinfo.isp'
    ])->toArray();

    if (isset($botStatus->meta) && $botStatus->meta->code === 200) {
      if ($botStatus->data->block_access === true) {
        $this->writeLog($selectedInfos);
      } else {
        $this->allows();
      }
    } else {
      $this->writeLog(['THERE SOMETHING ERROR ON KILLBOT.PW']);
    }
  }
}
