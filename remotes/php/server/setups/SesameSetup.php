<?php

#[Setup]
class SesameSetup {
    public static function configure(mixed $execution): array {
        return ['http' => ['sesame' => new SesameTransportHelper()]];
    }
}
