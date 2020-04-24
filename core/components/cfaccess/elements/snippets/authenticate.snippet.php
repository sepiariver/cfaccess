<?php
/**
 * cfa.Authenticate
 * @package cfaccess
 * Authenticate a request using the CF_Authorization cookie
 * 
 * @author @sepiariver <info@sepiariver.com>
 * Copyright 2020 by YJ Tso
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 **/

// OPTIONS
$authenticatedTpl = $modx->getOption('authenticatedTpl', $scriptProperties, '@INLINE  ', true); // Show to authorized users
$overrideAuthorizationRedirect = $modx->getOption('overrideAuthorizationRedirect', $scriptProperties, false); // USE WITH CAUTION
$obfuscate = $modx->getOption('obfuscate', $scriptProperties, true); // Obfuscate auth failure with 404
$unauthenticatedTpl = $modx->getOption('unauthenticatedTpl', $scriptProperties, '@INLINE  ', true); // Show to unauthorized
$runSnippetsOnAuth = $modx->getOption('runSnippetsOnAuth', $scriptProperties, ''); // Comma-separated list of Snippet names

// Grab the CFAccess class
$cfaccess = null;
$cfaccessPath = $modx->getOption('cfaccess.core_path', null, $modx->getOption('core_path') . 'components/cfaccess/');
$cfaccessPath .= 'model/cfaccess/';
if (file_exists($cfaccessPath . 'cfaccess.class.php')) $cfaccess = $modx->getService('cfaccess', 'CFAccess', $cfaccessPath);

// Validate
$valid = false;
if (!$cfaccess || !($cfaccess instanceof \SepiaRiver\CFAccess)) {
    $modx->log(modX::LOG_LEVEL_ERROR, '[cfa.Authenticate] could not load the required cfaccess class!');
} else {
    $valid = $cfaccess->validate(); // Check CF Authorization cookie
    if ($valid) {
        $snippets = $cfaccess->explodeAndClean($runSnippetsOnAuth);
        $props = $scriptProperties;
        $props['decoded_email'] = $cfaccess->getDecodedEmail();
        if (!empty($snippets)) {
            $snippetResults = $cfaccess->runSnippets($snippets, $scriptProperties);
            $props = array_merge($props, $snippetResults);
        }
        return $cfaccess->getChunk($authenticatedTpl, $props);
    }
}

// Treat as unauthorized if $cfaccess failed to instantiate
if ($overrideAuthorizationRedirect) {
    // Snippet call override: show content to unauthorized users
    return $cfaccess->getChunk($unauthenticatedTpl, []);
} else {
    if ($obfuscate) {
        // Default outcome for unauthorized users
        $modx->sendErrorPage();
    } else {
        // Send 401
        $modx->sendUnauthorizedPage();
    }
}