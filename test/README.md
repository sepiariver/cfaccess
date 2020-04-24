# Testing CFAccess

WARNING: Do not run tests in a production environment! This test suite makes modificatios to the MODX database.

1. From this directory `composer install`  
2. Ensure that a valid, working MODX `config.core.php` file exists in the project root.
3. CFAccess must be installed, or symlinked from the components folders. `ln -s /path/to/repo/core/components/cfaccess /path/to/modx/core/components/cfaccess`
3. Run `vendor/bin/phpunit`.