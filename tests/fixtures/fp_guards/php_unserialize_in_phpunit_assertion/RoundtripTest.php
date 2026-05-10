<?php
// PHPUnit test methods that round-trip a value through serialize() and
// then assert the unserialize() result equals a literal expected value.
// Drupal, Joomla, and Nextcloud each carry ~30 of these in their test
// trees.  The actionable signal is zero: the test inputs are
// developer-supplied and the assertion bounds the unserialize result
// to the literal expected value.  Suppress `php.deser.unserialize` on
// every shape below; firing on test-only assertions is noise.

use PHPUnit\Framework\TestCase;

class RoundtripTest extends TestCase
{
    public function testArrayLiteralExpected(): void
    {
        $blob = serialize(['a' => 1, 'b' => 2]);
        $this->assertSame(['a' => 1, 'b' => 2], unserialize($blob));
    }

    public function testNestedArrayLiteralExpected(): void
    {
        $blob = serialize([['k' => 'v'], 'tail']);
        $this->assertEquals([['k' => 'v'], 'tail'], unserialize($blob));
    }

    public function testScalarStringExpected(): void
    {
        $blob = 's:5:"hello";';
        $this->assertSame('hello', unserialize($blob));
    }

    public function testScalarIntegerExpected(): void
    {
        $blob = 'i:42;';
        $this->assertEquals(42, unserialize($blob));
    }

    public function testNullExpected(): void
    {
        $blob = 'N;';
        $this->assertNull(unserialize($blob));
    }

    public function testStaticCallScopeExpected(): void
    {
        $blob = serialize(['x']);
        static::assertSame(['x'], unserialize($blob));
    }

    public function testSelfCallScopeExpected(): void
    {
        $blob = serialize(['y']);
        self::assertEquals(['y'], unserialize($blob));
    }

    public function testCaseInsensitiveAssertionVerb(): void
    {
        $blob = serialize([true, false]);
        $this->AssertSame([true, false], unserialize($blob));
    }
}
