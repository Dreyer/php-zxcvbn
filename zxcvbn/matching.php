<?php

#namespace zxcbn\matching;

$GRAPHS = array();
$DICTIONARY_MATCHERS = array();

function translate( $string, $chr_map )
{
    $out = '';

    foreach ( str_split( $string ) as $char )
    {
        $out += ( isset( $char_map[$char] ) ? $char_map[$char] : $char );
    };

    return $out;
};

#-------------------------------------------------------------------------------
# dictionary match (common passwords, english, last names, etc) ----------------
#-------------------------------------------------------------------------------

function dictionary_match( $password, $ranked_dict )
{
    $result = array();
    $length = strlen( $password );

    $pw_lower = strtolower( $password );

    foreach ( range( 0, $length ) as $i )
    {
        foreach ( range( $i, $length ) as $j )
        {
            $word = substr( $pw_lower, $i, $j + 1 );

            if ( isset( $ranked_dict[$word] ) )
            {
                $rank = $ranked_dict[$word];

                $result[] = array(
                    'pattern' => 'dictionary',
                    'i' => $i,
                    'j' => $j,
                    'token' => substr( $password, $i, $j + 1 ),
                    'matched_word' => $word,
                    'rank' => $rank,
                );
            };
        };
    };

    return $result;
};

function _build_dict_matcher( $dict_name, $ranked_dict )
{
    return function( $password ) use ( $dict_name, $ranked_dict )
    {
        $matches = dictionary_match( $password, $ranked_dict );
        
        foreach ( $matches as $match )
        {
            $match['dictionary_name'] = $dict_name;
        };

        return $matches;
    };
};

function _build_ranked_dict( $unranked_list )
{
    $result = array();
    $i = 1;

    foreach ( $unranked_list as $word )
    {
        $result[$word] = $i;
        $i += 1;
    };
    
    return $result;
};

function _load_frequency_lists()
{
    global $DICTIONARY_MATCHERS;

    $data = file_get_contents( dirname( __FILE__ ) . '/generated/frequency_lists.json' );
    $dicts = json_decode( $data, $assoc = TRUE );

    foreach ( $dicts as $name => $wordlist )
    {
        $DICTIONARY_MATCHERS[] = _build_dict_matcher( $name, _build_ranked_dict( $wordlist ) );
    };
};

function _load_adjacency_graphs()
{
    global $GRAPHS;

    $data = file_get_contents( dirname( __FILE__ ) . '/generated/adjacency_graphs.json' );
    $GRAPHS = json_decode( $data, $assoc = TRUE );
};

# on qwerty, 'g' has degree 6, being adjacent to 'ftyhbv'. '\' has degree 1.
# this calculates the average over all keys.
function _calc_average_degree( $graph )
{
    $average = 0.0;

    foreach ( array_values( $graph ) as $neighbors )
    {
        foreach ( $neighbors as $n )
        {
            $list = array();

            if ( ! is_null( $n ) )
            {
                $list[] = $n;
            };

            $average += count( $list );
        };
    };

    $average /= count( $graph );
    
    return $average;
};

_load_frequency_lists();
_load_adjacency_graphs();

$KEYBOARD_AVERAGE_DEGREE = _calc_average_degree( $GRAPHS['qwerty'] );

# slightly different for keypad/mac keypad, but close enough
$KEYPAD_AVERAGE_DEGREE = _calc_average_degree( $GRAPHS['keypad'] );

$KEYBOARD_STARTING_POSITIONS = count( $GRAPHS['qwerty'] );
$KEYPAD_STARTING_POSITIONS = count( $GRAPHS['keypad'] );

#-------------------------------------------------------------------------------
# dictionary match with common l33t substitutions ------------------------------
#-------------------------------------------------------------------------------

$L33T_TABLE = array(
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

# makes a pruned copy of L33T_TABLE that only includes password's possible substitutions
function relevant_l33t_subtable( $password )
{
    global $L33T_TABLE;

    $password_chars = array_unique( str_split( $password ) );

    $filtered = array();

    foreach ( $L33T_TABLE as $letter => $subs )
    {
        $relevent_subs = array();

        foreach ( $subs as $sub )
        {
            if ( in_array( $sub, $password_chars ) )
            {
                $relevent_subs[] = $sub;
            };
        };

        if ( count( $relevent_subs ) )
        {
            $filtered[$letter] = $relevent_subs;
        };
    };

    return $filtered;
};

# returns the list of possible 1337 replacement dictionaries for a given password

function enumerate_l33t_subs( $table )
{
    $subs = array( array() );

    $dedup = function( $subs )
    {
        $deduped = array();
        $members = array();

        foreach ( $subs as $sub )
        {
            $key = implode( '', $sub[0] );

            if ( ! isset( $members[$key] ) )
            {
                $members[$key] = TRUE;
                $deduped[] = $sub;
            };
        };

        return $deduped;
    };

    $keys = array_keys( $table );

    while ( count( $keys ) > 0 )
    {
        $first_key = $keys[0];
        $rest_keys = array_slice( $keys, 1 );
        $next_subs = array();

        foreach ( $table[$first_key] as $l33t_chr )
        {
            foreach ( $subs as $sub )
            {
                $dup_l33t_index = -1;

                $sub_length = count( $sub );

                if ( $sub_length > 0  )
                {
                    foreach ( range( 0, $sub_length ) as $i )
                    {
                        if ( isset( $sub[$i][0] ) && $sub[$i][0] === $l33t_chr )
                        {
                            $dup_l33t_index = $i;

                            break;
                        };
                    };
                };

                if ( $dup_l33t_index == -1 )
                {
                    $sub_extension = $sub;
                    $sub_extension[] = array( $l33t_chr, $first_key );
                    $next_subs[] = $sub_extension;
                }
                else
                {
                    $sub_alternative = $sub;
                    array_splice( $sub_alternative, $dup_l33t_index, 1 );
                    $sub_alternative[] = array( $l33t_chr, $first_key );
                    $next_subs[] = $sub;
                    $next_subs[] = $sub_alternative;
                };
            };
        };

        $subs = $dedup( $next_subs );
        $keys = $rest_keys;
    };

    // convert from assoc lists to dicts.
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

function l33t_match( $password )
{
    global $DICTIONARY_MATCHERS;
    
    $sub_display = function( $match_sub )
    {
        $pieces = array();

        foreach ( $match_sub as $k => $v )
        {
            $pieces[] = sprintf( '%s -> %s', $k, $v );
        };

        return implode( ', ', $pieces );
    };

    $matches = array();

    $subtable = relevant_l33t_subtable( $password );

    if ( ! empty( $subtable ) )
    {
        foreach ( enumerate_l33t_subs( $subtable ) as $sub )
        {
            if ( count( $sub ) === 0 )
            {
                break;
            };

            $subbed_password = translate( $password, $sub );

            foreach ( $DICTIONARY_MATCHERS as $matcher )
            {
                foreach ( $matcher( $subbed_password ) as $match )
                {
                    $token = substr( $password, $match['i'], $match['j'] + 1 );

                    if ( strtolower( $token ) === $match['matched_word'] )
                    {
                        continue;
                    };

                    $match_sub = array();

                    foreach ( $sub as $subbed_chr => $char )
                    {
                        if ( stristr( $token, $subbed_chr ) )
                        {
                            $match_sub[$subbed_chr] = $char;
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
    }
    
    return $matches;
};


# ------------------------------------------------------------------------------
# spatial match (qwerty/dvorak/keypad) -----------------------------------------
# ------------------------------------------------------------------------------

function spatial_match( $password )
{
    global $GRAPHS;

    $matches = array();

    foreach ( $GRAPHS as $graph_name => $graph )
    {
        $matches = array_merge( $matches, spatial_match_helper( $password, $graph, $graph_name ) );
    };
    
    return $matches;
};

function spatial_match_helper( $password, $graph, $graph_name )
{
    $result = array();
    $i = 0;

    while ( $i < strlen( $password ) - 1 )
    {
        $j = $i + 1;
        $last_direction = NULL;
        $turns = 0;
        $shifted_count = 0;

        while ( TRUE )
        {
            $prev_char = $password[$j-1];
            $found = FALSE;
            $found_direction = -1;
            $cur_direction = -1;
            $adjacents = ( in_array( $prev_char, $graph ) ? $graph[$prev_char] : array() );
            # consider growing pattern by one character if j hasn't gone over the edge.
            if ( $j < strlen( $password ) )
            {
                $cur_char = $password[$j];

                foreach ( $adjacents as $adj )
                {
                    $cur_direction += 1;

                    if ( $adj && stristr( $adj, $cur_char ) )
                    {
                        $found = TRUE;
                        $found_direction = $cur_direction;

                        if ( strpos( $adj, $cur_char ) === 1 )
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
            # otherwise push the pattern discovered so far, if any...
            else
            {
                if ( $j - $i > 2 ) # don't consider length 1 or 2 chains.
                {
                    $result[] = array(
                        'pattern' => 'spatial',
                        'i' => $i,
                        'j' => $j - 1,
                        'token' => substr( $password, $i, $j ),
                        'graph' => $graph_name,
                        'turns' => $turns,
                        'shifted_count' => $shifted_count,
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

function repeat_match( $password )
{
    $groupby = function( $password )
    {
        $grouped = array();

        $password_chars = str_split( $password );

        $prev_char = NULL;
        $index = NULL;

        foreach ( $password_chars as $char )
        {
            if ( $prev_char === $char )
            {
                $grouped[$index] .= $char;
            }
            else
            {
                $index = ( is_null( $index ) ? 0 : $index + 1 );

                $grouped[$index] = $char;
            };
        };

        return $grouped;
    };

    $result = array();
    $repeats = $groupby( $password );
    $i = 0;

    foreach ( $repeats as $i => $group )
    {
        $group = str_split( $group );

        $char = $group[0];

        $length = count( $group );
        
        if ( $length > 2 )
        {
            $j = $i + $length - 1;

            $result[] = array(
                'pattern' => 'repeat',
                'i' => $i,
                'j' => $j,
                'token' => substr( $password, $i, $j + 1 ),
                'repeated_char' => $char,
            );
        };

        $i += $length;
    };

    return $result;
};

$SEQUENCES = array(
    'lower' => 'abcdefghijklmnopqrstuvwxyz',
    'upper' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
   'digits' => '01234567890',
);

function sequence_match( $password )
{
    global $SEQUENCES;

    $result = array();
    $i = 0;

    while ( $i < strlen( $password ) )
    {
        $j = $i + 1;
        $seq = NULL;           # either lower, upper, or digits
        $seq_name = NULL;
        $seq_direction = NULL; # 1 for ascending seq abcd, -1 for dcba

        foreach ( $SEQUENCES as $seq_candidate_name => $seq_candidate )
        {
            $i_n = strpos( $seq_candidate, $password[$i] );
            $j_n = ( $j < strlen( $password ) ? strpos( $seq_candidate, $password[$j] ) : -1 );

            if ( $i_n > -1 && $j_n > -1 )
            {
                $direction = $j_n - $i_n;

                if ( in_array( $direction, array( 1, -1 ) ) )
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
                if ( $j < strlen( $password ) )
                {
                    $prev_char = substr( $password, $j - 1 );
                    $cur_char = substr( $password, $j );

                    $prev_n = strpos( $seq_candidate, $prev_char );
                    $cur_n = strpos( $seq_candidate, $cur_char );
                };

                if ( ( $j === strlen( $password ) ) || ( ( $cur_n - $prev_n ) !== $seq_direction ) )
                {
                    if ( $j - $i > 2 ) # don't consider length 1 or 2 chains.
                    {
                        $result[] = array(
                            'pattern' => 'sequence',
                            'i' => $i,
                            'j' => $j - 1,
                            'token' => substr( $password, $i, $j ),
                            'sequence_name' => $seq_name,
                            'sequence_space' => strlen( $seq ),
                            'ascending' => ( $seq_direction === 1 ),
                        );
                    };

                    break;
                }
                else
                {
                    $j += 1;
                }
            };
        };

        $i = $j;
    };

    return $result;
};

#-------------------------------------------------------------------------------
# digits, years, dates ---------------------------------------------------------
#-------------------------------------------------------------------------------

function match_all( $password, $pattern_name, $regex )
{
    $out = array();

    preg_match_all( $regex, $password, $matches, PREG_PATTERN_ORDER );

    if ( isset( $matches[1] ) )
    {
        foreach ( $matches[1] as $match )
        {
            $i = strpos( $match );
            $j = $i + strlen( $match );

            $out[] = array(
                'pattern' => $pattern_name,
                'i' => $i,
                'j' => $j,
                'token' => substr( $password, $i, $j + 1 ),
            );
        };
    };

    return $out;
};


$DIGITS_MATCH = '/\d{3,}/';
function digits_match( $password )
{
    global $DIGITS_MATCH;

    return match_all( $password, 'digits', $DIGITS_MATCH );
};

$YEAR_MATCH = '/19\d\d|200\d|201\d/';
function year_match( $password )
{
    global $YEAR_MATCH;

    return match_all( $password, 'year', $YEAR_MATCH );
};

function date_match( $password )
{
    $l = date_without_sep_match( $password );
    $l[] = date_sep_match( $password );

    return $l;
};

$DATE_WITHOUT_SEP_MATCH = '/\d{4,8}/';
function date_without_sep_match( $password )
{
    global $DATE_WITHOUT_SEP_MATCH;

    $date_matches = array();
    
    $found = preg_match_all( $DATE_WITHOUT_SEP_MATCH, $password, $matches, PREG_OFFSET_CAPTURE );

    if ( $found && isset( $matches[0] ) )
    {
        foreach ( $matches[0] as $digit_match )
        {
            list( $token, $offset ) = $digit_match;

            // position of match.
            $token_length = strlen( $token );
            $i = $offset;
            $j = $token_length;

            $candidates_round_1 = array(); # parse year alternatives

            if ( $token_length <= 6 )
            {
                # 2-digit year prefix
                $candidates_round_1[] = array(
                    'daymonth' => substr( $token, 2 ),
                    'year' => substr( $token, 0, 2 ),
                    'i' => $i,
                    'j' => $j,
                );

                # 2-digit year suffix
                $candidates_round_1[] = array(
                    'daymonth' => substr( $token, 0, $token_length - 2 ),
                    'year' => substr( $token, $token_length - 2 ),
                    'i' => $i,
                    'j' => $j,
                );
            };

            if ( $token_length >= 6 )
            {
                # 4-digit year prefix
                $candidates_round_1[] = array(
                    'daymonth' => substr( $token, 4 ),
                    'year' => substr( $token, 0, 4 ),
                    'i' => $i,
                    'j' => $j,
                );

                # 4-digit year suffix
                $candidates_round_1[] = array(
                    'daymonth' => substr( $token, 0, $token_length - 4 ),
                    'year' => substr( $token, $token_length - 4 ),
                    'i' => $i,
                    'j' => $j,
                );
            };

            $candidates_round_2 = array(); # parse day/month alternatives

            foreach ( $candidates_round_1 as $candidate )
            {
                $daymonth_length = strlen( $candidate['daymonth'] );

                if ( $daymonth_length === 2 ) # ex. 1 1 97
                {
                    $candidates_round_2[] = array(
                        'day' => substr( $candidate['daymonth'], 0, 1 ),
                        'month' => substr( $candidate['daymonth'], 1, 1 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j'],
                    );
                }
                elseif ( $daymonth_length === 3 ) # ex. 11 1 97 or 1 11 97
                {
                    $candidates_round_2[] = array(
                        'day' => substr( $candidate['daymonth'], 0, 2 ),
                        'month' => substr( $candidate['daymonth'], 2, 1 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j'],
                    );

                    $candidates_round_2[] = array(
                        'day' => substr( $candidate['daymonth'], 0, 1 ),
                        'month' => substr( $candidate['daymonth'], 1, 2 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j'],
                    );
                    
                }
                elseif ( $daymonth_length === 4 ) # ex. 11 11 97
                {
                    $candidates_round_2[] = array(
                        'day' => substr( $candidate['daymonth'], 0, 2 ),
                        'month' => substr( $candidate['daymonth'], 2, 2 ),
                        'year' => $candidate['year'],
                        'i' => $candidate['i'],
                        'j' => $candidate['j'],
                    );
                };
            };

            # final loop: reject invalid dates
            foreach ( $candidates_round_2 as $candidate )
            {
                if ( ! isset( $candidate['day'], $candidate['month'], $candidate['year'] ) )
                {
                    continue;
                };

                $day = ( integer ) $candidate['day'];
                $month = ( integer ) $candidate['month'];
                $year = ( integer ) $candidate['year'];

                list( $valid, list( $day, $month, $year ) ) = check_date( $day, $month, $year );

                if ( ! $valid )
                {
                    continue;
                };

                $date_matches[] = array(
                    'pattern' => 'date',
                    'i' => $candidate['i'],
                    'j' => $candidate['j'],
                    'token' => $token,
                    'separator' => '',
                    'day' => $day,
                    'month' => $month,
                    'year' => $year,
                );
            };
        };
    };

    return $date_matches;
};

$DATE_RX_YEAR_SUFFIX = '~(\d{1,2})(\s|-|/|\\|_|\.)(\d{1,2})\2(19\d{2}|200\d|201\d|\d{2})~';
#$DATE_RX_YEAR_SUFFIX = '/(\d{1,2})(\s|-|/|\\|_|\.)/';
$DATE_RX_YEAR_PREFIX = '~(19\d{2}|200\d|201\d|\d{2})(\s|-|/|\\|_|\.)(\d{1,2})\2(\d{1,2})~';

function date_sep_match( $password )
{
    global $DATE_RX_YEAR_SUFFIX, $DATE_RX_YEAR_PREFIX;

    $matches = array();

    $found = preg_match_all( $DATE_RX_YEAR_SUFFIX, $password, $suffix, PREG_OFFSET_CAPTURE );

    if ( $found && isset( $suffix ) )
    {
        for ( $i = 0; $i < $found; $i++ )
        {
            $matches[] = array(
                'day'   => ( integer ) $suffix[1][$i][0],
                'month' => ( integer ) $suffix[3][$i][0],
                'year'  => ( integer ) $suffix[4][$i][0],
                'sep'   => $suffix[2][$i][0],
                'i'     => $suffix[0][$i][1],
                'j'     => $suffix[0][$i][1] + ( strlen( $suffix[0][$i][0] ) ),
            );
        };
    };

    $found = preg_match_all( $DATE_RX_YEAR_PREFIX, $password, $prefix, PREG_OFFSET_CAPTURE );

    if ( $found && isset( $prefix ) )
    {
        for ( $i = 0; $i < $found; $i++ )
        {
            $matches[] = array(
                'day'   => ( integer ) $prefix[4][$i][0],
                'month' => ( integer ) $prefix[3][$i][0],
                'year'  => ( integer ) $prefix[1][$i][0],
                'sep'   => $prefix[2][$i][0],
                'i'     => $prefix[0][$i][1],
                'j'     => $prefix[0][$i][1] + ( strlen( $prefix[0][$i][0] ) ),
            );
        };
    };

    $date_matches = array();

    foreach ( $matches as $match )
    {
        list( $valid, list( $day, $month, $year ) ) = check_date( $match['day'], $match['month'], $match['year'] );

        if ( ! $valid )
        {
            continue;
        };

        $date_matches[] = array(
            'pattern' => 'date',
            'i' => $match['i'],
            'j' => $match['j'] - 1,
            'token' => substr( $password, $match['i'], $match['j'] ),
            'separator' => $match['sep'],
            'day' => $day,
            'month' => $month,
            'year' => $year,
        );
    };

    return $date_matches;
};

function check_date( $day, $month, $year )
{
    // tolerate both day-month and month-day order.
    if ( 12 <= $month && $month <= 31 && $day <= 12 )
    {
        $day = $month; 
        $month = $day;
    };

    if ( $day > 31 || $month > 12 )
    {
        return array( FALSE, array( 0, 0, 0 ) );
    };

    if ( ! ( 1900 <= $year && $year <= 2019 ) )
    {
        return array( FALSE, array( 0, 0, 0 ) );
    };

    return array( TRUE, array( $day, $month, $year ) );
};


$MATCHERS = $DICTIONARY_MATCHERS;
$MATCHERS = array_merge( $MATCHERS, array(
    'l33t_match',
    'digits_match', 'year_match', 'date_match',
    'repeat_match', 'sequence_match',
    'spatial_match'
) );

function omnimatch( $password, $user_inputs = array() )
{
    global $MATCHERS;

    $ranked_user_inputs_dict = array();

    foreach ( $user_inputs as $i => $user_input )
    {
        $ranked_user_inputs_dict[strtlower( $user_input )] = $i + 1;
    };

    $user_input_matcher = _build_dict_matcher( 'user_inputs', $ranked_user_inputs_dict );
    $matches = $user_input_matcher( $password );

    foreach ( $MATCHERS as $matcher )
    {
        $result = $matcher( $password );

        $matches = array_merge( $matches, $result );
    };

    $compare_function = function( $a, $b )
    {
        if ( ! isset( $a['i'], $b['i'], $a['j'], $b['j'] ) )
        {
            return 0;
        };

        return ( $a['i'] - $b['i'] ) || ( $a['j'] - $b['j'] );
    };

    usort( $matches, $compare_function );

    return $matches;
};
?>