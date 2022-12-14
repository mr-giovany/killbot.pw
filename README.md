# Wrapper for KILLBOT.PW

installing dependency by typing:

> composer require kgsdev/killbot.pw

Create file index.php and paste the code below:

```plaintext
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Kgsdev\Killbot;

class MyKillBot extends Killbot
{
  /**
   * apiKey
   *
   * KILLBOT.PW APIKEY
   * find your key at: https://killbot.org/dashboard
   * 
   * @return string
   */
  public function apiKey()
  {
    return '';
  }

  /**
   * url for allowed visitor
   * redirect if the visitor isnt bot
   * 
   * @return string
   */
  public function botRedirect()
  {
    return 'https://google.com';
  }

  /**
   * whiteLists
   *
   * list of white listed IPS
   * 
   * @return array
   */
  public function whiteLists()
  {
    return [
      '127.0.0.1'
    ];
  }

  /**
   * logsFile
   * 
   * log file name
   * 
   * @return void
   */
  public function logsFile()
  {
    return 'visitor.logs';
  }

  public function __invoke()
  {
    if (collect($this->whiteLists())->contains($this->ipv4())) {
      return $this->writeLog(['WHITE LISTED!']);
    }

    if ($this->botRedirect() != $this->currentURL()) {
      $this->runBlocker();
    }
  }
}
```
