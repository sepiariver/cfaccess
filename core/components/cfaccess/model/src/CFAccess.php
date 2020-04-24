<?php 
namespace SepiaRiver;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use \GuzzleHttp\Client;
use \modX;
use \xPDO;

/**
 * The main MRAdmin service class.
 *
 * @package cfaccess
 */
class CFAccess {
    public $modx = null;
    public $namespace = 'cfaccess';
    public $options = [];
    public static $version = '0.0.1';
    public $logLevel = modX::LOG_LEVEL_DEBUG;
    public $client = null;
    protected $decoded = null;
    protected $userId = null;
    const ALL_CTX_KEY = 'cfaccess_all_contexts';

    public function __construct(modX &$modx, array $options = []) {
        $this->modx =& $modx;
        $this->namespace = $this->getOption('namespace', $options, 'cfaccess');

        $corePath = $this->getOption('core_path', $options, $this->modx->getOption('core_path', null, MODX_CORE_PATH) . 'components/cfaccess/');
        $assetsPath = $this->getOption('assets_path', $options, $this->modx->getOption('assets_path', null, MODX_ASSETS_PATH) . 'components/cfaccess/');
        $assetsUrl = $this->getOption('assets_url', $options, $this->modx->getOption('assets_url', null, MODX_ASSETS_URL) . 'components/cfaccess/');

        /* loads some default paths for easier management */
        $this->options = array_merge(array(
            'namespace' => $this->namespace,
            'corePath' => $corePath,
            'modelPath' => $corePath . 'model/',
            'vendorPath' => $corePath . 'model/vendor/',
            'assetsPath' => $assetsPath,
            'assetsUrl' => $assetsUrl,
            'jsUrl' => $assetsUrl . 'js/',
            'cssUrl' => $assetsUrl . 'css/',
            'connectorUrl' => $assetsUrl . 'connector.php'
        ), $options);

        // sets up autoload and pkg in modx
        require_once($this->options['vendorPath'] . 'autoload.php');
        $this->modx->addPackage('cfaccess', $this->getOption('modelPath'));
        //$this->modx->lexicon->load('cfaccess:default');
        
        // class variables
        if ($this->getOption('debug')) $this->logLevel = modX::LOG_LEVEL_ERROR;
    }

    /**
     * getClient
     * Return or initialize Guzzle HTTP client
     * 
     * @return null|\GuzzleHttp\Client
     */
    protected function getClient($reInit = false)
    {   
        if ($this->client instanceof Client && !$reInit) {
            return $this->client;
        }
        $url = $this->getSystemSetting('auth_url');
        if (empty($url)) {
            $this->log('Missing auth_url system setting!');
            return null;
        }
        $this->client = new Client(['base_uri' => $url]);
        if (!($this->client instanceof Client)) {
            $this->log('Could not instantiate http client!'); // @codeCoverageIgnore
            return null; // @codeCoverageIgnore
        }
        return $this->client;
    }

    /**
     * getJWKs
     * Fetch JWKs from Cloudflare
     * 
     * @return array
     */
    protected function getJWKs()
    {
        $keys = []; 

        // Get client
        $client = $this->getClient();
        if (!$client) return $keys;

        // Get certs
        $resp = $client->request('GET', '/cdn-cgi/access/certs');
        $json = (string) $resp->getBody();
        $keySet = json_decode($json, true);

        // Parse jwk
        if ($keySet) {
            try {
                $keys = JWK::parseKeySet($keySet);
            } catch (\Exception $e) { // @codeCoverageIgnore
                $this->log($e->getMessage()); // @codeCoverageIgnore
            } 
        }

        return $keys;
    }

    /**
     * getDecodedEmail
     * Returns the email from the decoded JWT payload
     * 
     * @return string
     */
    public function getDecodedEmail()
    {
        if (!is_object($this->decoded) || !isset($this->decoded->email)) {
            return '';
        }
        return $this->decoded->email;
    }

    /**
     * findUserId
     * Quick searches for a MODX User ID
     * 
     * @var $this->decoded->email 
     * 
     * @return bool
     */
    protected function findUserId()
    {
        $email = $this->getDecodedEmail();
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false; // @codeCoverageIgnore
        }

        // Find matching modUser username
        $userQuery = $this->modx->newQuery('modUser', [
            'username' => $email
        ]);
        if (!$userQuery) return false;
        $userQuery->select('id');
        $this->userId = $this->modx->getValue($userQuery->prepare());
        if ($this->userId) return true;

        // Failing that, match email in profile
        $profileQuery = $this->modx->newQuery('modUserProfile', [
            'email' => $email
        ]);
        if (!$profileQuery) return false;
        $profileQuery->select('internalKey');
        $this->userId = $this->modx->getValue($profileQuery->prepare());
        if ($this->userId) return true;

        // We found nothing
        return false; // @codeCoverageIgnore
    }

    /**
     * validate
     * Validates the CF_Authorization cookie
     * 
     * @return bool
     */
    public function validate() 
    {   
        // Get keyset
        $keys = $this->getJWKs();
        if (empty($keys)) return false;

        // Get audience tag
        $aud = $this->getSystemSetting('auth_aud');
        if (empty($aud)) {
            $this->log('Missing audience tag!');
            return false;
        }

        // Get token
        $token = $_COOKIE['CF_Authorization'];
        if (empty($token)) return false;

        // Validate token
        $valid = false;
        foreach ($keys as $key) {
            try {
                $this->decoded = JWT::decode($token, $key, ['RS256']);
                if ($this->decoded && is_array($this->decoded->aud)) {
                    foreach ($this->decoded->aud as $a) {
                        if ($a === $aud) {
                            // Valid token
                            if ($this->getSystemSetting('require_moduser')) {
                                // Must match modUser username
                                $found = $this->findUserId();
                                if ($found && $this->userId) {
                                    $valid = true;
                                    if ($this->getSystemSetting('assign_moduser')) {
                                        // Attempt to assign modx->user
                                        $user = $this->modx->getObject('modUser', $this->userId);
                                        if ($user) $this->modx->user = $user;
                                    }
                                }
                            } else {
                                // modUser not required
                                $valid = true;
                            }
                            // We found a valid token
                            break 2;
                        }
                    }
                }
            } catch (\Exception $e) {
                $this->log($e->getMessage());
            }
        }

        return $valid;
    }

    /**
     * checkContext
     * Evaluates whether to check the supplied Context
     * Note: it does not actually check the Context, but decides
     * whether or not checking should be done.
     * 
     * @param $ctx (string) Context key
     * 
     * @return bool
     */
    public function checkContext(string $ctx)
    {
        $contexts =  $this->explodeAndClean($this->getSystemSetting('contexts'));
        if (in_array(self::ALL_CTX_KEY, $contexts)) {
            return true;
        } else {
            return (in_array($ctx, $contexts));
        }
    }

    /**
     * runSnippets
     * calls $modx->runSnippet on an array of Snippet names
     * 
     * @param array $snippets Array of Snippets by name
     * @param array $properties Array of namespaced Snippet properties
     * 
     * @return array Array of results
     */
    public function runSnippets(array $snippets, array $properties)
    {
        $results = [];
        foreach ($snippets as $snippet) {
            $props = $this->getNsOptions($properties, $snippet);
            $results[$snippet] = $this->modx->runSnippet($snippet, $props);
        }
        return $results;
    }

    /**
     * log
     * Logs according to $this->logLevel and returns an array of log data
     * 
     * @param string $msg Error message to log
     * @param mixed  $data Data to log
     * 
     * @return array $toLog Array of log data 
     */
    public function log(string $msg, $data = '') 
    {
        $level = $this->logLevel;
        $toLog = [];
        // Format log data
        if (is_scalar($data)) {
            $toLog['data'] = (string) $data;
        } elseif (method_exists($data, 'toArray')) {
            $toLog['data'] = $data->toArray();
        } else {
            $toLog['data'] = (array) $data;  // @codeCoverageIgnore
        }
        
        // Add stack trace to ERROR level logs
        if ($level === modX::LOG_LEVEL_ERROR) {
            $bt = debug_backtrace(0, 2);
            $toLog['caller'] = $bt[1];
        }

        // Output 
        $json = $this->modx->toJSON($toLog);
        $this->modx->log($level, $msg . PHP_EOL . $json);
        $toLog['message'] = $msg; // exclude from $json above
        return $toLog;
    }

    /**
     * Get a namespaced system setting directly from the modSystemSetting table.
     * Does not allow cascading Context, User Group, nor User settings, like the name suggests.
     *
     * @param string $key The option key to search for.
     * @param mixed $default The default value returned if the option is not found as a
     * namespaced system setting; by default this value is ''.
     * @return mixed The option value or the default value specified.
     */
    protected function getSystemSetting($key = '', $default = '')
    {
        if (empty($key)) return $default;
        $query = $this->modx->newQuery('modSystemSetting', [
            'key' => "{$this->namespace}.{$key}",
        ]);
        $query->select('value');
        $value = $this->modx->getValue($query->prepare());
        if ($value === false || $value === null) $value = $default;
        return $value;
    }

    /**
     * getNsOptions
     * Get namespaced options
     * 
     * @param array $array      Array to process
     * @param string $prefix    String prefix to filter
     * @param string $delim     String delimiter
     * @TODO: make recursive?
     * @return array            Array of namespaced config options
     */
    public function getNsOptions(array $array = null, string $prefix = '', string $delim = '_')
    {
        $result = [];
        if (empty($array)) return $result;
        foreach ($array as $k => $v) {
            if (strpos($k, $prefix) === 0) {
                $k = ltrim(substr($k, strlen($prefix)), $delim);
                $result[$k] = $v;
            }
        }
        return $result;
    }

    // UTILITY methods based on theboxer's work //

    /**
     * Get a local configuration option or a namespaced system setting by key.
     *
     * @param string $key The option key to search for.
     * @param array $options An array of options that override local options.
     * @param mixed $default The default value returned if the option is not found locally or as a
     * namespaced system setting; by default this value is null.
     * @return mixed The option value or the default value specified.
     */
     public function getOption($key = '', $options = [], $default = null)
     {
         $option = $default;
         if (!empty($key) && is_string($key)) {
             if (is_array($options) && array_key_exists($key, $options)) {
                 // Simple array access
                 $option = $options[$key];
             } elseif (is_array($options) && array_key_exists("{$this->namespace}.{$key}", $options)) {
                 // Namespaced properties like formit->config
                 $option = $options["{$this->namespace}.{$key}"];
             } elseif (array_key_exists($key, $this->options)) {
                 // Instance config
                 $option = $this->options[$key];
             } elseif (array_key_exists("{$this->namespace}.{$key}", $this->modx->config)) {
                 // Namespaced system settings
                 $option = $this->modx->getOption("{$this->namespace}.{$key}");
             }
         }
         return $option;
     }

    /**
     * Transforms a string to an array with removing duplicates and empty values
     *
     * @param $string
     * @param string $delimiter
     * @return array
     */
    public function explodeAndClean($string, $delimiter = ',')
    {
        $string = (string) $string;
        $array = explode($delimiter, $string);    // Explode fields to array
        $array = array_map('trim', $array);       // Trim array's values
        $array = array_keys(array_flip($array));  // Remove duplicate fields
        $array = array_filter($array);            // Remove empty values from array
        return $array;
    }

    /**
     * Processes a chunk or given string
     *
     * @param string $tpl
     * @param array $phs
     * @return string
     */
    public function getChunk($tpl = '', $phs = [])
    {
        if (empty($tpl)) return '';
        if (!is_array($phs)) $phs = [];
        if (strpos($tpl, '@INLINE ') !== false) {
            $content = str_replace('@INLINE ', '', $tpl);
            /** @var \modChunk $chunk */
            $chunk = $this->modx->newObject('modChunk', array('name' => 'inline-' . uniqid()));
            $chunk->setCacheable(false);
            return $chunk->process($phs, $content);
        }
        // Not strictly necessary but helpful in common error scenario
        if ($this->modx->getCount('modChunk', ['name' => $tpl]) !== 1) {
            $this->modx->log(modX::LOG_LEVEL_ERROR, 'CFAccess: no Chunk with name ' . $tpl);
            return '';
        }
        return $this->modx->getChunk($tpl, $phs);
    }

}