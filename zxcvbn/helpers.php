<?php
    
    function _get_frequency_lists()
    {
        $lists = array();

        $json = file_get_contents( dirname( __FILE__ ) . '/generated/frequency_lists.json' );
        $rows = json_decode( $json, $assoc = TRUE );

        foreach ( $rows as $name => $wordlist )
        {
            $lists[] = build_dict_matcher( $name, build_ranked_dict( $wordlist ) );
        };

        return $lists;
    };
    
    function _get_adjacency_graphs()
    {
        $json = file_get_contents( dirname( __FILE__ ) . '/generated/adjacency_graphs.json' );
        $rows = json_decode( $json, $assoc = TRUE );

        return $rows;
    };

    function _get_index( $arr, $index )
    {
        return ( ( $index < 0 ) || ( $index >= count( $arr ) ) ? 0 : $arr[$index] );
    };

    function _slice( $str, $start, $stop = NULL )
    {
        $pieces = array();

        $stop = ( is_null( $stop ) ? strlen( $str ) : $stop );

        $chars = str_split( $str );

        for ( $i = $start; $i < $stop; $i++ )
        {
            if ( isset( $chars[$i] ) )
            {
                $pieces[] = $chars[$i];
            };
        };

        return ( count( $pieces ) ? implode( '', $pieces ) : NULL );
    };

    function _char_at( $str, $i )
    {
        return ( strlen( $str ) > $i ? $str{$i} : '' );
    };

    function _index_of( $str, $chr = NULL )
    {
        $pos = @strpos( $str, $chr );

        return ( $pos === FALSE ? -1 : $pos );
    };

    /*
    function is_lower( $ord )
    {
        return ( $ord >= 0x61 && $ord <= 0x7a );
    };

    function is_digit( $ord )
    {
        return ( $ord >= 0x30 && $ord <= 0x39 );
    };

    function is_upper( $ord )
    {
        return ( $ord >= 0x41 && $ord <= 0x5a );
    };

    function is_alpha( $ord )
    {
        return ( is_upper( $ord ) || is_lower( $ord ) );
    };
    */
?>