<?php

namespace Stermedia\AppDevSecurity;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\Yaml\Parser;
use Symfony\Component\Yaml\Exception\ParseException;

/**
 * Class AppDevSecurity
 * This tool handle access to debug front controllers that are deployed by to production servers.
 * Uses parameters defined in
 * @author Jakub Paszkiewicz <jacobmaster17@gmail.com>
 * @license MIT
 */
class AppDevSecurityHandler
{
    /**
     * Config dir path - path to symfony config dir
     *
     * @var string
     */
    protected $configDir;

    /**
     * $_SERVER - Server and execution environment information
     *
     * @var array
     */
    protected $server;

    /**
     * Is app_dev security disabled
     *
     * @var bool
     */
    protected $securityDisabled;

    /**
     * Is HTTP_CLIENT_IP allowed
     *
     * @var bool
     */
    protected $allowHttpClientIp;

    /**
     * Is HTTP_X_FORWARDED_FOR allowed
     *
     * @var bool
     */
    protected $allowHttpXForwardedFor;

    /**
     * Array of disallowed types of interface between web server and PHP(the Server API, SAPI)
     * uses php_sapi_name()
     *
     * @var array
     */
    protected $disallowedPhpSapiNames;

    /**
     * Array of allowed remote ip addresses. Compares to REMOTE_ADDR
     *
     * @var array
     */
    protected $allowedRemoteAddr;

    /**
     * Constructor
     *
     * @param string $configDir path to symfony config dir
     * @param array  $server    $_SERVER - Server and execution environment information
     */
    public function __construct($configDir = null, $server = null)
    {
        if(is_null($configDir)) {
            $this->configDir = __DIR__.'/../../../app/config/';
        } else {
            $this->configDir = $configDir;
        }
        if(is_null($server)) {
            $this->server = $_SERVER;
        } else {
            $this->server = $server;
        }

        // set defaults
        $this->securityDisabled= false;
        $this->allowHttpClientIp = false;
        $this->allowHttpXForwardedFor = false;
        $this->disallowedPhpSapiNames = array ('cli-server');
        $this->allowedRemoteAddr = array (
            '127.0.0.1',
            'fe80::1',
            '::1'
        );

        $this->loadParameters();
    }

    /**
     * Returns absolute config dir path
     *
     * @return string
     */
    protected function getConfigDir()
    {

        return $this->configDir;
    }

    /**
     * Load parameters file (yml)
     *
     * @return bool|string
     */
    protected function loadParametersFile()
    {
        $locator = new FileLocator(array($this->getConfigDir()));
        $parametersFile = $locator->locate('parameters.yml');
        $parameters = file_get_contents($parametersFile);

        return $parameters;
    }

    /**
     * Parse loaded parameters file (yml) using Symfony Yaml Parser
     *
     * @param $parametersFile
     *
     * @return bool|mixed
     */
    protected function parseParametersFile($parametersFile)
    {
        $yaml = new Parser();
        try {
            $parsedParametersFile = $yaml->parse($parametersFile);
        } catch (ParseException $e) {

            return false;
        }

        return $parsedParametersFile;
    }

    /**
     * Loads parameters form file
     *
     * @return bool
     */
    protected function loadParameters()
    {
        $parametersFile = $this->loadParametersFile();
        if (!$parametersFile) {
            return false;
        }

        $parsedParametersFile = $this->parseParametersFile($parametersFile);

        if (!$parsedParametersFile) {

            return false;
        }

        if (!isset($parsedParametersFile['parameters'])) {

            return false;
        }

        $parameters = $parsedParametersFile['parameters'];

        if (isset($parameters['app_dev_security_disable'])) {
            $this->securityDisabled = filter_var(
                $parameters['app_dev_security_disable'],
                FILTER_VALIDATE_BOOLEAN
            );
        }
        if (!$this->securityDisabled) {
            if (isset($parameters['app_dev_security_allow_http_client_ip'])) {
                $this->allowHttpClientIp = filter_var(
                    $parameters['app_dev_security_allow_http_client_ip'],
                    FILTER_VALIDATE_BOOLEAN
                );
            }

            if (isset($parameters['app_dev_security_allow_http_x_forwarded_for'])) {
                $this->allowHttpXForwardedFor = filter_var(
                    $parameters['app_dev_security_allow_http_x_forwarded_for'],
                    FILTER_VALIDATE_BOOLEAN
                );
            }

            if (isset($parameters['app_dev_security_disallowed_php_sapi_names'])
                && is_array($parameters['app_dev_security_disallowed_php_sapi_names'])
            ) {
                $this->disallowedPhpSapiNames = $parameters['app_dev_security_disallowed_php_sapi_names'];
            }

            if (isset($parameters['app_dev_security_allowed_remote_addr'])
                && is_array($parameters['app_dev_security_allowed_remote_addr'])
            ) {
                $this->allowedRemoteAddr = $parameters['app_dev_security_allowed_remote_addr'];
            }
        }

        return true;
    }

    /**
     * Returns forbidden message
     *
     * @return string
     */
    public function getForbiddenMessage()
    {

        return 'You are not allowed to access this file.';
    }

    /**
     * Returns Forbidden header
     *
     * @return string
     */
    public function getForbiddenHeader()
    {

        return 'HTTP/1.0 403 Forbidden';
    }

    /**
     * Checks if debug front controller is accessible
     *
     * @return bool
     */
    public function isAccessible()
    {

        if ($this->securityDisabled) {
            return true;
        }

        if (!$this->allowHttpClientIp) {
            if (isset($this->server['HTTP_CLIENT_IP'])) {

                return false;
            }
        }

        if (!$this->allowHttpXForwardedFor) {
            if (isset($this->server['HTTP_X_FORWARDED_FOR'])) {

                return false;
            }
        }

        if (!in_array(@$this->server['REMOTE_ADDR'], $this->allowedRemoteAddr)) {

            return false;
        }

        if (in_array(php_sapi_name(), $this->disallowedPhpSapiNames)) {

            return false;
        }

        return true;
    }
}
