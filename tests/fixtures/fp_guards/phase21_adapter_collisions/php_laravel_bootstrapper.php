<?php

class Bootstrapper
{
    public function configure($app)
    {
        return $app->withMiddleware([]);
    }
}
