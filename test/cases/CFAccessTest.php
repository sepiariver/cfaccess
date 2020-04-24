<?php
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Error\Deprecated;
use PHPUnit\Framework\Error\Warning;
use PHPUnit\Framework\Error\Notice;
use Symfony\Component\Dotenv\Dotenv;
use SepiaRiver\CFAccess;

class CFAccessTest extends TestCase
{
    protected $projectPath;
    protected $modx;
    protected $cfaccess; // gateway class
    
    protected function setUp(): void
    {
        # Deprecated:
        Deprecated::$enabled = FALSE;

        $this->projectPath = dirname(dirname(dirname(__FILE__)));
        $dotenv = new Dotenv();
        try {
            $dotenv->load($this->projectPath . '/test/.env');
        } catch (\Exception $e) {
            echo $e->getMessage();
        }

        require_once($this->projectPath . '/config.core.php');
        require_once(MODX_CORE_PATH . 'model/modx/modx.class.php');
        $this->modx = new \modX();
        $this->modx->initialize('web');

        $corePath = $this->modx->getOption('cfaccess.core_path', null, $this->modx->getOption('core_path', null, MODX_CORE_PATH) . 'components/cfaccess/');
        /** @var CFAccess $cfaccess */
        $this->cfaccess = $this->modx->getService('cfaccess', 'CFAccess', $corePath . 'model/cfaccess/', ['core_path' => $corePath]);

    }

    public function testInstantiation()
    {
        $this->assertTrue($this->modx instanceof \modX);
        $this->assertTrue($this->modx->context instanceof \modContext);
        $this->assertEquals('web', $this->modx->context->key);
        $this->assertTrue($this->cfaccess instanceof CFAccess);
        $this->assertEquals('', $this->cfaccess->getDecodedEmail());
        
       
        $prefix = $this->cfaccess->namespace . '.';
        // Anti-pattern
        $this->url = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'auth_url']);
        $this->url->set('value', '');
        $this->url->save();
        $this->assertFalse($this->cfaccess->validate());
        $this->url->set('value', $_ENV['URL']);
        $this->url->save();
        $this->aud = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'auth_aud']);
        $this->aud->set('value', '');
        $this->aud->save();
        $this->assertFalse($this->cfaccess->validate());
        $this->aud->set('value', $_ENV['AUD']);
        $this->aud->save();
        
    }

    public function testValidate()
    {
        $prefix = $this->cfaccess->namespace . '.';

        $req = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'require_moduser']);
        $req->set('value', 0);
        $req->save();
        $asn = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'assign_moduser']);
        $asn->set('value', 0);
        $asn->save();

        $_COOKIE['CF_Authorization'] = $_ENV['JWT'];

        $this->assertTrue($this->cfaccess->validate());
        $this->assertEquals($_ENV['MODUSER_EMAIL'], $this->cfaccess->getDecodedEmail());
    }

    public function testValidateUser()
    {
        $prefix = $this->cfaccess->namespace . '.';

        $req = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'require_moduser']);
        $req->set('value', 1);
        $req->save();
        $asn = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'assign_moduser']);
        $asn->set('value', 1);
        $asn->save();
        $_COOKIE['CF_Authorization'] = $_ENV['JWT'];

        $this->assertTrue($this->cfaccess->validate());
        $this->assertEquals($this->cfaccess->modx->user->id, $_ENV['MODUSER_ID']);
        
    }

    public function testSnippet()
    {
        $props = [
            'authenticatedTpl' => '@INLINE Authed',
            'unauthenticatedTpl' => '@INLINE Not Authed',
            'overrideAuthorizationRedirect' => 1
        ];
        $_COOKIE['CF_Authorization'] = $_ENV['JWT'];
        $result = $this->modx->runSnippet('cfa.Authenticate', $props);
        $this->assertEquals('Authed', $result);

        $_COOKIE['CF_Authorization'] = 'foobar';
        $result = $this->modx->runSnippet('cfa.Authenticate', $props);
        $this->assertEquals('Not Authed', $result);
    }

    public function testRunSnippets()
    {
        $name = 'inline-' . uniqid();
        /** @var \modSnippet $snippet */
        $snippet = $this->modx->newObject('modSnippet', ['name' => $name, 'snippet' => 'return "foobar" . $modx->getOption("test", $scriptProperties);']);
        $snippet->save();
        $log = $this->cfaccess->log('log message', $snippet);
        $this->assertEquals($snippet->toArray(), $log['data']);

        $results = $this->cfaccess->runSnippets([$name], [$name . '_test' => 'testing']);
        $this->assertEquals([$name => "foobartesting"], $results);
        $this->assertTrue($snippet->remove());
    }

    public function testContextCheck()
    {
        $prefix = $this->cfaccess->namespace . '.';

        $name = uniqid();
        $ctx = $this->modx->getObject('modSystemSetting', ['key' => $prefix . 'contexts']);
        $ctx->set('value', 'temp');
        $ctx->save();
        $this->assertFalse($this->cfaccess->checkContext($name));
        $ctx->set('value', $name);
        $ctx->save();
        $this->assertTrue($this->cfaccess->checkContext($name));
        $name = $this->cfaccess::ALL_CTX_KEY;
        $ctx->set('value', $name);
        $ctx->save();
        $this->assertTrue($this->cfaccess->checkContext($name));
    }

    public function testUtilities()
    {
        $name = uniqid();
        $this->assertEquals('', $this->cfaccess->getChunk($name));

        $chunk = $this->modx->newObject('modChunk', ['name' => $name, 'snippet' => 'foobar']);
        $chunk->save();
        $this->assertEquals('foobar', $this->cfaccess->getChunk($name));
        $this->assertTrue($chunk->remove());

        $this->assertEquals('foobar', $this->cfaccess->getOption('foo', [$this->cfaccess->namespace . '.foo' => 'foobar']));
    }

}
