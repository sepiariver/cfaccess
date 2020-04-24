<?php
/**
 * CFA Authenticate
 * @package cfaccess
 * Authenticate requests for Resources in a configured Context 
 * using the CF_Authorization cookie; manage IP caching
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
$obfuscate = $modx->getOption('obfuscate', $scriptProperties, true); // Obfuscate auth failure with 404

// Exit early if the wrong Event is attached
$event = $modx->event->name;
if (!in_array($event, ['OnWebPageInit'])) return;

// Grab the CFAccess class
$cfaccess = null;
$cfaccessPath = $modx->getOption('cfaccess.core_path', null, $modx->getOption('core_path') . 'components/cfaccess/');
$cfaccessPath .= 'model/cfaccess/';
if (file_exists($cfaccessPath . 'cfaccess.class.php')) $cfaccess = $modx->getService('cfaccess', 'CFAccess', $cfaccessPath);
if (!$cfaccess || !($cfaccess instanceof \SepiaRiver\CFAccess)) {
    $modx->log(modX::LOG_LEVEL_ERROR, '[CFA Authenticate] could not load the required cfaccess class!');
    return;
} 

// Support triggering on different events
switch ($event) {
    case 'OnWebPageInit':
        if ($cfaccess->checkContext($modx->context->key)) { // Configured to check this Context
            if (!$cfaccess->validate()) {
                if ($obfuscate) {
                    // Default outcome for unauthorized users
                    $modx->sendErrorPage();
                } else {
                    // Send 401
                    $modx->sendUnauthorizedPage();
                }
            }
        }
        // Pass through un-checked. No locking.
    break;
    default: 
    break;
}