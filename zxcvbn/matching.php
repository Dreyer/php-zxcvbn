<?php

/*
function empty( obj )
{
    return ( count( array_keys( $obj ) ) === 0 );
};
*/

function extend( &$arr1, $arr2 )
{
    $arr1 = array_merge( $arr1, $arr2 );
};

function translate( $str, $chr_map )
{
    $results = array();

    foreach ( str_split( $str ) as $chr )
    {
        $results[] = ( isset( $chr_map[$chr] ) ? $chr_map[$chr] : $chr );
    };

    return implode( '', $results );
};

# ------------------------------------------------------------------------------
# omnimatch -- combine everything ----------------------------------------------
# ------------------------------------------------------------------------------

function omnimatch( $password )
{
    global $MATCHERS;

    $matches = array();

    foreach ( $MATCHERS as $matcher )
    {
        extend( $matches, $matcher( $password ) );
    };

    $compare_function = function( $match1, $match2 )
    {
        return ( $match1['i'] - $match2['i'] ) or ( $match1['j'] - $match2['j'] );
    };

    usort( $matches, $compare_function );

    return $matches;
};

#-------------------------------------------------------------------------------
# dictionary match (common passwords, english, last names, etc) ----------------
#-------------------------------------------------------------------------------

function dictionary_match( $password, $ranked_dict )
{
    $result = array();

    $len = strlen( $password );
    $password_lower = strtolower( $password );

    for ( $i = 0; $i < $len; $i++ )
    {
        for ( $j = $i; $j < $len; $j++)
        {
            $word = _slice( $password_lower, $i, $j + 1 );

            if ( isset( $ranked_dict[$word] ) )
            {
                $rank = $ranked_dict[$word];

                $result[] = array(
                    'pattern' => 'dictionary',
                    'i' => $i,
                    'j' => $j,
                    'token' => _slice( $password, $i, $j + 1 ),
                    'matched_word' => $word,
                    'rank' => $rank
                );
            };
        };
    };

    return $result;
};

function build_ranked_dict( $unranked_list )
{
    $result = array();
    $i = 1; # rank starts at 1, not 0

    foreach ( $unranked_list as $word )
    {
        $result[$word] = $i;
        $i += 1;
    };

    return $result;
};

function build_dict_matcher( $dict_name, $ranked_dict )
{   
    return function( $password ) use ( $dict_name, $ranked_dict )
    {
        $matches = dictionary_match( $password, $ranked_dict );

        foreach ( $matches as &$match )
        {
            $match['dictionary_name'] = $dict_name;
        };

        return $matches;
    };
};

#-------------------------------------------------------------------------------
# dictionary match with common l33t substitutions ------------------------------
#-------------------------------------------------------------------------------

$l33t_table = array(
    'a' => array( '4', '@' ),
    'b' => array( '8' ),
    'c' => array( '(', '{', '[', '<' ),
    'e' => array( '3' ),
    'g' => array( '6', '9' ),
    'i' => array( '1', '!', '|' ),
    'l' => array( '1', '|', '7' ),
    'o' => array( '0' ),
    's' => array( '$', '5' ),
    't' => array( '+', '7' ),
    'x' => array( '%' ),
    'z' => array( '2' ),
);

# makes a pruned copy of l33t_table that only includes password's possible substitutions
function relevent_l33t_subtable( $password )
{
    global $l33t_table;

    $password_chars = array();

    foreach ( str_split( $password ) as $chr )
    {
        $password_chars[$chr] = TRUE;
    };

    $filtered = array();

    foreach ( $l33t_table as $letter => $subs )
    {
        $relevent_subs = array();

        foreach ( $subs as $sub )
        {
            if ( isset( $password_chars[$sub] ) )
            {
                $relevent_subs[] = $sub;
            };
        };

        if ( ! empty( $relevent_subs ) )
        {
            $filtered[$letter] = $relevent_subs;
        };
    };

    return $filtered;
};

# returns the list of possible 1337 replacement dictionaries for a given password
function enumerate_l33t_subs( $table )
{
    $keys = array_keys( $table );

    $subs = array( array() );

    $dedup = function( $subs )
    {
        $deduped = array();
        $members = array();

        foreach ( $subs as $sub )
        {
            $assoc = array();

            foreach ( $sub as $k => $v )
            {
                $assoc[] = array( $k, $v );
            };

            sort( $assoc, SORT_REGULAR );

            $labels = array();

            foreach ( $assoc as $a )
            {
                $labels[] = serialize( $a );
            };

            $label = implode( '-', $labels );

            if ( ! isset( $members[$label] ) )
            {
                $members[$label] = TRUE;
                $deduped[] = $sub;
            };
        };

        return $deduped;
    };

    $helper = function( $keys ) use ( $table, &$subs, $dedup, &$helper )
    {
        if ( empty( $keys ) )
        {
            return;
        };

        $first_key = $keys[0];
        $rest_keys = array_slice( $keys, 1 );
        $next_subs = array();

        foreach ( $table[$first_key] as $l33t_chr )
        {
            foreach ( $subs as $sub )
            {
                $dup_l33t_index = -1;

                $sub_len = count( $sub );

                for ( $i = 0; $i < $sub_len; $i++ )
                {
                    if ( $sub[$i][0] === $l33t_chr )
                    {
                        $dup_l33t_index = $i;

                        break;
                    };
                };

                if ( $dup_l33t_index === -1 )
                {
                    $sub_extension = $sub;
                    $sub_extension[] = array( $l33t_chr, $first_key );
                    $next_subs[] = $sub_extension;
                }
                else
                {
                    $sub_alternative = array_slice( $sub, 0 );
                    array_splice( $sub_alternative, $dup_l33t_index, 1 );
                    $sub_extension[] = array( $l33t_chr, $first_key );
                    $next_subs[] = $sub;
                    $next_subs[] = $sub_alternative;
                };
            };
        };

        $subs = $dedup( $next_subs );

        return $helper( $rest_keys );
    };

    $helper( $keys );

    # convert from assoc lists to dicts
    $sub_dicts = array();

    foreach ( $subs as $sub )
    {
        $sub_dict = array();

        foreach ( $sub as $s )
        {
            list( $l33t_chr, $chr ) = $s;

            $sub_dict[$l33t_chr] = $chr;
        };

        $sub_dicts[] = $sub_dict;
    };

    return $sub_dicts;
};


$l33t_match = function( $password )
{
    global $DICTIONARY_MATCHERS;

    $matches = array();
    
    $sub_display = function( $match_sub )
    {
        $pieces = array();

        foreach ( $match_sub as $k => $v )
        {
            $pieces[] = sprintf( '%s -> %s', $k, $v );
        };

        return implode( ', ', $pieces );
    };

    $l33t_subs = enumerate_l33t_subs( relevent_l33t_subtable( $password ) );

    foreach ( $l33t_subs as $sub )
    {
        # corner case: password has no relevent subs.
        if ( empty( $sub ) )
        {
            break;
        };

        foreach ( $DICTIONARY_MATCHERS as $matcher )
        {
            $subbed_password = translate( $password, $sub );

            $matched = $matcher( $subbed_password );

            foreach ( $matched as $match )
            {
                $token = _slice( $password, $match['i'], $match['j'] + 1 );

                # only return the matches that contain an actual substitution
                if ( strtolower( $token ) === $match['matched_word'] )
                {
                    continue;
                };

                # subset of mappings in sub that are in use for this match
                $match_sub = array();
                
                foreach ( $sub as $subbed_chr => $chr )
                {
                    if ( _index_of( $token, ( string ) $subbed_chr ) !== -1 )
                    {
                        $match_sub[$subbed_chr] = $chr;
                    };
                };

                $match['l33t'] = TRUE;
                $match['token'] = $token;
                $match['sub'] = $match_sub;
                $match['sub_display'] = $sub_display( $match_sub );

                $matches[] = $match;
            };
        };
    };

    return $matches;
};

# ------------------------------------------------------------------------------
# spatial match (qwerty/dvorak/keypad) -----------------------------------------
# ------------------------------------------------------------------------------

$spatial_match = function( $password )
{
    global $GRAPHS;

    $matches = array();

    foreach ( $GRAPHS as $graph_name => $graph )
    {
        extend( $matches, spatial_match_helper( $password, $graph, $graph_name ) );
    };

    return $matches;
};

function spatial_match_helper( $password, $graph, $graph_name )
{
    $result = array();
    $i = 0;

    $password_len = strlen( $password );

    while ( $i < $password_len - 1 )
    {
        $j = $i + 1;
        $last_direction = NULL;
        $turns = 0;
        $shifted_count = 0;

        while ( TRUE )
        {
            $prev_char = _char_at( $password, $j - 1 );
            $found = FALSE;
            $found_direction = -1;
            $cur_direction = -1;
            $adjacents = ( isset( $graph[$prev_char] ) ? $graph[$prev_char] : array() );
            
            # consider growing pattern by one character if j hasn't gone over the edge.
            if ( $j < $password_len )
            {
                $cur_chr = _char_at( $password, $j );

                foreach ( $adjacents as $adj )
                {
                    $cur_direction += 1;

                    $cur_chr_pos = _index_of( $adj, $cur_chr );

                    if ( $adj && $cur_chr_pos !== -1 )
                    {
                        $found = TRUE;
                        $found_direction = $cur_direction;

                        if ( $cur_chr_pos === 1 )
                        {
                            # index 1 in the adjacency means the key is shifted, 0 means unshifted: A vs a, % vs 5, etc.
                            # for example, 'q' is adjacent to the entry '2@'. @ is shifted w/ index 1, 2 is unshifted.
                            $shifted_count += 1;
                        };

                        if ( $last_direction !== $found_direction )
                        {
                            # adding a turn is correct even in the initial case when last_direction is null:
                            # every spatial pattern starts with a turn.
                            $turns += 1;
                            $last_direction = $found_direction;
                        };

                        break;
                    };
                };
            };

            # if the current pattern continued, extend j and try to grow again
            if ( $found )
            {
                $j += 1; 
            }
            else # otherwise push the pattern discovered so far, if any...
            {
                if ( $j - $i > 2 ) # don't consider length 1 or 2 chains.
                {
                    $result[] = array(
                        'pattern' => 'spatial',
                        'i' => $i,
                        'j' => $j - 1,
                        'token' => _slice( $password, $i, $j ),
                        'graph' => $graph_name,
                        'turns' => $turns,
                        'shifted_count' => $shifted_count
                    );
                };
                
                # ...and then start a new search for the rest of the password.
                $i = $j;

                break;
            };
        };
    };

    return $result;
};

#-------------------------------------------------------------------------------
# repeats (aaa) and sequences (abcdef) -----------------------------------------
#-------------------------------------------------------------------------------

$repeat_match = function( $password )
{
    $result = array();
    $i = 0;

    while ( $i < strlen( $password ) )
    {
        $j = $i + 1;

        while ( TRUE )
        {
            if ( _char_at( $password, $j - 1 ) === _char_at( $password, $j ) )
            {
                $j += 1;
            }
            else
            {
                if ( $j - $i > 2 ) # don't consider length 1 or 2 chains.
                {
                    $result[] = array(
                        'pattern' => 'repeat',
                        'i' => $i,
                        'j' => $j - 1,
                        'token' => _slice( $password, $i, $j ),
                        'repeated_char' => _char_at( $password, $i )
                    );
                };

                break;
            };
        };

        $i = $j;
    };

    return $result;
};

$SEQUENCES = array(
    'lower' => 'abcdefghijklmnopqrstuvwxyz',
    'upper' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'digits' => '01234567890'
);

$sequence_match = function( $password ) use ( $SEQUENCES )
{
    $result = array();
    $i = 0;
    
    while ( $i < strlen( $password ) )
    {
        $j = $i + 1;
        $seq = NULL; # either lower, upper, or digits
        $seq_name = NULL;
        $seq_direction = NULL; # 1 for ascending seq abcd, -1 for dcba

        foreach ( $SEQUENCES as $seq_candidate_name => $seq_candidate )
        {
            $i_n = _index_of( $seq_candidate, _char_at( $password, $i ) );
            $j_n = _index_of( $seq_candidate, _char_at( $password, $j ) );

            if ( $i_n > -1 && $j_n > -1 )
            {
                $direction = $j_n - $i_n;

                #if ( in_array( $direction, array( 1, -1 ) ) )
                if ( $direction === 1 || $direction === ( -1 ) )
                {
                    $seq = $seq_candidate;
                    $seq_name = $seq_candidate_name;
                    $seq_direction = $direction;

                    break;
                };
            };
        };

        if ( $seq )
        {
            while ( TRUE )
            {
                $sliced = _slice( $password, $j - 1, $j + 1 );
                $prev_chr = substr( $sliced, 0, 1 );
                $cur_chr = substr( $sliced, 1, 1 );

                $prev_n = _index_of( $seq_candidate, $prev_chr );
                $cur_n = _index_of( $seq_candidate, $cur_chr );

                if ( $cur_n - $prev_n === $seq_direction )
                {
                    $j += 1;
                }
                else
                { 
                    # don't consider length 1 or 2 chains.
                    if ( $j - $i > 2 )
                    {
                        $result[] = array(
                            'pattern' => 'sequence',
                            'i' => $i,
                            'j' => $j - 1,
                            'token' => _slice( $password, $i, $j ),
                            'sequence_name' => $seq_name,
                            'sequence_space' => strlen( $seq ),
                            'ascending' => ( $seq_direction === 1 )
                        );
                    };

                    break;
                };
            };
        };
        
        $i = $j;
    };

    return $result;
};

#-------------------------------------------------------------------------------
# digits, years, dates ---------------------------------------------------------
#-------------------------------------------------------------------------------

function repeat( $chr, $n )
{
    return str_repeat( $chr, $n );
};

function findall( $password, $rx )
{
    $matches = array();

    while ( TRUE )
    {
        $count = preg_match_all( $rx, $password, $captures );

        if ( ! $count )
        {
            break;
        };

        for ( $i = 0; $i < $count; $i++ )
        {   
            $match = array();

            foreach ( $captures as $m )
            {
                $match[] = $m[$i];
            };

            $match['index'] = strpos( $password, $match[0] );
            $match['input'] = $password;
            $match['length'] = strlen( $match[0] );

            $match['i'] = $match['index'];
            #$match['j'] = $match['length'];  
            $match['j'] = $match['index'] + ( $match['length'] - 1 );

            $matches[] = $match;

            $password = str_replace( $match[0], repeat( ' ', $match['length'] ), $password );
        };
    };

    return $matches;
};

$digits_rx = '/(\d{3,})/';

$digits_match = function( $password ) use ( $digits_rx )
{
    $results = array();

    foreach ( findall( $password, $digits_rx ) as $match )
    {
        $i = $match['i'];
        $j = $match['j'];

        $results[] = array(
            'pattern' => 'digits',
            'i' => $i,
            'j' => $j,
            'token' => _slice( $password, $i, $j + 1 )
        );
    };

    return $results;
};

# 4-digit years only. 2-digit years have the same entropy as 2-digit brute force.
$year_rx = '/(19\d\d|200\d|201\d)/';

$year_match = function( $password ) use ( $year_rx )
{
    $results = array();

    foreach ( findall( $password, $year_rx ) as $match )
    {
        $i = $match['i'];
        $j = $match['j'];

        $results[] = array(
            'pattern' => 'year',
            'i' => $i,
            'j' => $j,
            'token' => _slice( $password, $i, $j + 1 )
        );
    };

    return $results;
};

$date_match = function( $password )
{
    # match dates with separators 1/1/1911 and dates without 111997
    return array_merge( 
        date_without_sep_match( $password ),
        date_sep_match( $password )
    );
};

function date_without_sep_match( $password )
{
    $date_matches = array();

    # 1197 is length-4, 01011997 is length 8
    foreach ( findall( $password, '/(\d{4,8})/' ) as $digit_match )
    {
        $i = $digit_match['i'];
        $j = $digit_match['j'];

        $token = _slice( $password, $j, $j + 1 );
        $token_len = strlen( $token );

        # parse year alternatives
        $candidates_round_1 = array();

        if ( $token_len <= 6 )
        {
            $candidates_round_1[] = array(
                'daymonth' => _slice( $token, 2 ),
                'year' => _slice( $token, 0, 2 ),
                'i' => $i,
                'j' => $j
            );

            $candidates_round_1[] = array(
                'daymonth' => _slice( $token, 0, ( $token_len - 2 ) ),
                'year' => _slice( $token, ( $token_len - 2 ) ),
                'i' => $i,
                'j' => $j
            );
        };

        if ( $token_len >= 6 )
        {
            $candidates_round_1[] = array(
                'daymonth' => _slice( $token, 4 ),
                'year' => _slice( $token, 0, 4 ),
                'i' => $i,
                'j' => $j
            );

            $candidates_round_1[] = array(
                'daymonth' => _slice( $token, 0, ( $token_len - 4 ) ),
                'year' => _slice( $token, ( $token_len - 4 ) ),
                'i' => $i,
                'j' => $j
            );
        };
        
        # parse day/month alternatives
        $candidates_round_2 = array();

        foreach ( $candidates_round_1 as $candidate )
        {
            switch ( strlen( $candidate['daymonth'] ) )
            {
                case 2: # ex. 1 1 97
                    $candidates_round_2[] = array(
                        'day' => _char_at( $candidate['daymonth'], 0 ),
                        'month' => _char_at( $candidate['daymonth'], 1 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j']
                    );
                    break;
                case 3: # ex. 11 1 97 or 1 11 97
                    $candidates_round_2[] = array(
                        'day' => _slice( $candidate['daymonth'], 0, 2 ),
                        'month' => _char_at( $candidate['daymonth'], 2 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j']
                    );
                    $candidates_round_2[] = array(
                        'day' => _char_at( $candidate['daymonth'], 0 ),
                        'month' => _slice( $candidate['daymonth'], 1, 3 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j']
                    );
                    break;
                case 4: # ex. 11 11 97
                    $candidates_round_2[] = array(
                        'day' => _slice( $candidate['daymonth'], 0, 2 ),
                        'month' => _slice( $candidate['daymonth'], 2, 4 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j']
                    );
                    break;
            };
        };

        # final loop: reject invalid dates
        foreach ( $candidates_round_2 as $candidate )
        {
            $day = ( integer ) $candidate['day'];
            $month = ( integer ) $candidate['month'];
            $year = ( integer ) $candidate['year'];

            list( $valid, $date ) = check_date( $day, $month, $year );
            
            if ( ! $valid )
            {
                continue;
            };

            list( $day, $month, $year ) = $date;

            $date_matches[] = array(
                'pattern' => 'date',
                'i' => $candidate['i'],
                'j' => $candidate['j'],
                'token' => _slice( $password, $i, $j + 1 ),
                'separator' => '',
                'day' => $day,
                'month' => $month,
                'year' => $year
            );
        };
    };

    return $date_matches;
};

$date_rx_year_suffix = '/(\d{1,2})(\s|-|\/|\\|_|\.)(\d{1,2})\2(19\d{2}|200\d|201\d|\d{2})/';

$date_rx_year_prefix = '/(19\d{2}|200\d|201\d|\d{2})(\s|-|\/|\\|_|\.)(\d{1,2})\2(\d{1,2})/';

function date_sep_match( $password )
{
    global $date_rx_year_suffix, $date_rx_year_prefix;

    $matches = array();
    
    foreach ( findall( $password, $date_rx_year_suffix ) as $match )
    {
        $match['day'] = ( integer ) $match[1];
        $match['month'] = ( integer ) $match[3];
        $match['year'] = ( integer ) $match[4];
        $match['sep'] = $match[2];

        $matches[] = $match;
    };
    
    foreach ( findall( $password, $date_rx_year_prefix ) as $match )
    {
        $match['day'] = ( integer ) $match[4];
        $match['month'] = ( integer ) $match[3];
        $match['year'] = ( integer ) $match[1];
        $match['sep'] = $match[2];

        $matches[] = $match;
    };

    $results = array();

    foreach ( $matches as $match )
    {
        list( $valid, $date ) = check_date( 
                                    $match['day'], 
                                    $match['month'], 
                                    $match['year'] 
                                );
        
        if ( ! $valid )
        {
            continue;
        };

        list( $day, $month, $year ) = $date;

        $i = $match['i'];
        $j = $match['j'];

        $results[] = array(
            'pattern' => 'date',
            'i' => $i,
            'j' => $j,
            'token' => _slice( $password, $i, $j + 1 ),
            'separator' => $match['sep'],
            'day' => $day,
            'month' => $month,
            'year' => $year
        );
    };

    return $results;
};

function check_date( $day, $month, $year )
{
    # tolerate both day-month and month-day order
    if ( ( 12 <= $month && $month <= 31 ) && $day <= 12 )
    {
        $m = $month;
        $month = $day;
        $day = $m;
    };

    if ( $day > 31 || $month > 12 )
    {
        return array( FALSE, array() );
    };

    if ( ! ( ( 1900 <= $year && $year <= 2019 ) ) )
    {
        return array( FALSE, array() );
    }

    return array( TRUE, array( $day, $month, $year ) );
};
?>