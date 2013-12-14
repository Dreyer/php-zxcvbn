<?php

    require 'helpers.php';
    require 'matching.php';
    require 'scoring.php';

    $ranked_user_inputs_dict = array();

    /*
    $DICTIONARY_MATCHERS = array(
        build_dict_matcher( 'passwords', build_ranked_dict( $passwords ) ), 
        build_dict_matcher( 'english', build_ranked_dict( $english ) ), 
        build_dict_matcher( 'male_names', build_ranked_dict( $male_names ) ), 
        build_dict_matcher( 'female_names', build_ranked_dict( $female_names ) ), 
        build_dict_matcher( 'surnames', build_ranked_dict( $surnames ) ), 
        build_dict_matcher( 'user_inputs', $ranked_user_inputs_dict )
    );

    $GRAPHS = array(
        'qwerty' => $qwerty,
        'dvorak' => $dvorak,
        'keypad' => $keypad,
        'mac_keypad' => $mac_keypad
    );
    */

    $DICTIONARY_MATCHERS   = _get_frequency_lists();
    $DICTIONARY_MATCHERS[] = build_dict_matcher( 'user_inputs', $ranked_user_inputs_dict );
    
    $GRAPHS = _get_adjacency_graphs();

    $MATCHERS = array_merge( $DICTIONARY_MATCHERS, array(
        $l33t_match, 
        $digits_match, 
        $year_match, 
        $date_match, 
        $repeat_match, 
        $sequence_match, 
        $spatial_match
    ) );

    function calc_average_degree( $graph )
    {
        $average = 0;
        $key;

        foreach ( $graph as $neighbors )
        {
            $results = array();
            $len = count( $neighbors );
            $i;

            for ( $i = 0; $i < $len; $i++ )
            {
                $n = $neighbors[$i];

                if ( $n )
                {
                    $results[] = $n;
                };
            };

            $average += count( $results );
        };

        $average /= count( array_keys( $graph ) );;

        return $average;
    };

    $KEYBOARD_AVERAGE_DEGREE = calc_average_degree( $GRAPHS['qwerty'] );

    $KEYPAD_AVERAGE_DEGREE = calc_average_degree( $GRAPHS['keypad'] );

    $KEYBOARD_STARTING_POSITIONS = count( array_keys( $GRAPHS['qwerty'] ) );

    $KEYPAD_STARTING_POSITIONS = count( array_keys( $GRAPHS['keypad'] ) );

    function zxcvbn( $password, $user_inputs = NULL )
    {
        $start = microtime( TRUE );

        if ( $user_inputs !== NULL )
        {
            $len = count( $user_inputs );
            $i;
            for ( $i = 0; $i < $len; $i++)
            {
                $ranked_user_inputs_dict[$user_inputs[$i]] = $i + 1;
            };
        };

        $matches = omnimatch( $password );
        $result = minimum_entropy_match_sequence( $password, $matches );
        
        $result['calc_time'] = microtime( TRUE ) - $start;
        
        return $result;
    };

    function password_strength( $password, $user_inputs = array() )
    {
        return zxcvbn( $password, $user_inputs );

        $time_start = microtime( TRUE );
    };
?>