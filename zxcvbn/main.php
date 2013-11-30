<?php

    require 'matching.php';
    require 'scoring.php';

    #use \zxcbn\matching as matching;
    #use \zxcbn\scoring as scoring;

    function password_strength( $password, $user_inputs = array() )
    {
        $time_start = microtime( TRUE );

        $matches = omnimatch( $password, $user_inputs );
        $result = minimum_entropy_match_sequence( $password, $matches );

        $result['calc_time'] = microtime( TRUE ) - $time_start;

        return $result;
    };
?>