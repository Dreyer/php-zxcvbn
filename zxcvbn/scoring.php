<?php

# Returns binomial_coefficiential coefficient (n choose k).
# http://blog.plover.com/math/choose.html
function binomial_coefficient( $n, $k )
{
    if ( $k > $n )
    {
        return 0;
    };

    if ( $k === 0 )
    {
        return 1;
    };

    $r = 1;

    foreach ( range( 1, $k ) as $d )
    {
        $r *= $n;
        $r /= $d;
        $n -= 1;
    };

    return $r;
};

# Returns logarithm of n in base 2.
function logarithm( $n )
{
    return log( $n, 2 );
};

# ------------------------------------------------------------------------------
# minimum entropy search -------------------------------------------------------
# ------------------------------------------------------------------------------
#
# takes a list of overlapping matches, returns the non-overlapping sublist with
# minimum entropy. O(nm) dp alg for length-n password with m candidate matches.
# ------------------------------------------------------------------------------

function minimum_entropy_match_sequence( $password, $matches )
{
    # e.g. 26 for lowercase
    $bruteforce_cardinality = calc_bruteforce_cardinality( $password );
    
    # minimum entropy up to k.
    $up_to_k = array();
    
    # for the optimal sequence of matches up to k, holds the 
    # final match (match.j == k). null means the sequence ends 
    # w/ a brute-force character.
    $backpointers = array();
    
    $password_len = strlen( $password );
    for ( $k = 0; $k < $password_len; $k++ )
    {
        # starting scenario to try and beat: 
        # adding a brute-force character to the minimum entropy sequence at k-1.
        $up_to_k[$k] = _get_index( $up_to_k, $k - 1 ) 
                     + logarithm( $bruteforce_cardinality );

        $backpointers[$k] = NULL;

        foreach ( $matches as $match )
        {
            if ( $match['j'] !== $k )
            {
                continue;
            };

            $i = $match['i']; 
            $j = $match['j'];

            # see if best entropy up to i-1 + entropy of this match 
            # is less than the current minimum at j.
            $candidate_entropy = _get_index( $up_to_k, $i - 1 ) 
                               + calc_entropy( $match );
            
            if ( $candidate_entropy < $up_to_k[$j] )
            {
                $up_to_k[$j] = $candidate_entropy;
                $backpointers[$j] = $match;
            };
        };
    };

    # walk backwards and decode the best sequence
    $match_sequence = array();
    $k = strlen( $password ) - 1;

    while ( $k >= 0 )
    {
        $match = $backpointers[$k];

        if ( $match )
        {
            $match_sequence[] = $match;

            $k = $match['i'] - 1;
        }
        else
        {
            $k -= 1;
        };
    };

    $match_sequence = array_reverse( $match_sequence );

    # fill in the blanks between pattern matches with bruteforce "matches"
    # that way the match sequence fully covers the password: 
    # match1.j == match2.i - 1 for every adjacent match1, match2.
    $make_bruteforce_match = function( $i, $j ) use ( $password, $bruteforce_cardinality )
    {
        return array(
            'pattern' => 'bruteforce',
            'i' => $i,
            'j' => $j,
            'token' => _slice( $password, $i, $j + 1 ),
            'entropy' => logarithm( pow( $bruteforce_cardinality, $j - $i + 1 ) ),
            'cardinality' => $bruteforce_cardinality,
        );
    };

    $k = 0;
    $match_sequence_copy = array();

    foreach ( $match_sequence as $match )
    {
        $i = $match['i'];
        $j = $match['j'];

        if ( $i - $k > 0 )
        {
            $match_sequence_copy[] = $make_bruteforce_match( $k, $i - 1 );
        };

        $k = $j + 1;

        $match_sequence_copy[] = $match;
    };

    if ( $k < strlen( $password ) )
    {
        $match_sequence_copy[] = $make_bruteforce_match( $k, strlen( $password ) - 1 );
    };

    $match_sequence = $match_sequence_copy;

    # or 0 corner case is for an empty password ''
    if ( isset( $up_to_k[strlen( $password ) - 1] ) )
    {
        $min_entropy = $up_to_k[strlen( $password ) - 1];
    }
    else
    {
        $min_entropy = 0;
    };

    $crack_time = entropy_to_crack_time( $min_entropy );

    # final result object
    $result = array(
        'password' => $password,
        'entropy' => round_to_x_digits( $min_entropy, 3 ),
        'match_sequence' => $match_sequence,
        'crack_time_seconds' => round_to_x_digits( $crack_time, 3 ),
        'crack_time_display' => display_time( $crack_time ),
        'score' => crack_time_to_score( $crack_time ),
    );

    return $result;
};

# Returns 'number' rounded to 'digits' digits.
function round_to_x_digits( $n, $x )
{
    return round( $n * pow( 10, $x ) ) / pow( 10, $x );
};

# ------------------------------------------------------------------------------
# threat model -- stolen hash catastrophe scenario -----------------------------
# ------------------------------------------------------------------------------
#
# assumes:
# * passwords are stored as salted hashes, different random salt per user.
#   (making rainbow attacks infeasable.)
# * hashes and salts were stolen. attacker is guessing passwords at max rate.
# * attacker has several CPUs at their disposal.
# ------------------------------------------------------------------------------

# for a hash function like bcrypt/scrypt/PBKDF2, 10ms per guess is a safe lower bound.
# (usually a guess would take longer -- this assumes fast hardware and a small work factor.)
# adjust for your site accordingly if you use another hash function, possibly by
# several orders of magnitude!
$SINGLE_GUESS = 0.010;
$NUM_ATTACKERS = 100; # number of cores guessing in parallel.

$SECONDS_PER_GUESS = $SINGLE_GUESS / $NUM_ATTACKERS;


function entropy_to_crack_time( $entropy )
{
    global $SECONDS_PER_GUESS;
    
    # average, not total
    return ( 0.5 * pow( 2, $entropy ) ) * $SECONDS_PER_GUESS;
};

function crack_time_to_score( $seconds )
{
    if ( $seconds < pow( 10, 2 ) )
    {
        return 0;
    };

    if ( $seconds < pow( 10, 4 ) )
    {
        return 1;
    };

    if ( $seconds < pow( 10, 6 ) )
    {
        return 2;
    };

    if ( $seconds < pow( 10, 8 ) )
    {
        return 3;
    };

    return 4;
};

# ------------------------------------------------------------------------------
# entropy calcs -- one function per match pattern ------------------------------
# ------------------------------------------------------------------------------

function calc_entropy( &$match )
{
    # a match's entropy doesn't change. cache it.
    if ( isset( $match['entropy'] ) )
    {
        return $match['entropy'];
    };

    if ( $match['pattern'] === 'repeat' )
    {
        $entropy_func = 'repeat_entropy';
    }
    elseif ( $match['pattern'] === 'sequence' )
    {
        $entropy_func = 'sequence_entropy';
    }
    elseif ( $match['pattern'] === 'digits' )
    {
        $entropy_func = 'digits_entropy';
    }
    elseif ( $match['pattern'] === 'year' )
    {
        $entropy_func = 'year_entropy';
    }
    elseif ( $match['pattern'] === 'date' )
    {
        $entropy_func = 'date_entropy';
    }
    elseif ( $match['pattern'] === 'spatial' )
    {
        $entropy_func = 'spatial_entropy';
    }
    elseif ( $match['pattern'] === 'dictionary' )
    {
        $entropy_func = 'dictionary_entropy';
    };

    $match['entropy'] = $entropy_func( $match );

    return $match['entropy'];
};

function repeat_entropy( $match )
{
    $cardinality = calc_bruteforce_cardinality( $match['token'] );
    $entropy = logarithm( $cardinality * strlen( $match['token'] ) );

    return $entropy;
};

function sequence_entropy( $match )
{
    $first_chr = $match['token']{ 0 };

    if ( in_array( $first_chr, array( 'a', '1' ) ) )
    {
        $base_entropy = 1;
    }
    else
    {
        if ( preg_match( '/\d/', $first_chr ) ) # digits
        {
            $base_entropy = logarithm( 10 );
        }
        elseif ( preg_match( '/[a-z]/', $first_chr ) ) # lower
        {
            $base_entropy = logarithm( 26 );
        }
        else # extra bit for uppercase
        {
            $base_entropy = logarithm( 26 ) + 1;
        };
    };
    
    # extra bit for descending instead of ascending
    if ( ! $match['ascending'] )
    {
        $base_entropy += 1;
    };

    return $base_entropy + logarithm( strlen( $match['token'] ) );
};

function digits_entropy( $match )
{
    return logarithm( pow( 10, strlen( $match['token'] ) ) );
};

$NUM_YEARS = 119; # years match against 1900 - 2019
$NUM_MONTHS = 12;
$NUM_DAYS = 31;

function year_entropy( $match )
{
    global $NUM_YEARS;

    return logarithm( $NUM_YEARS );
};

function date_entropy( $match )
{
    global $NUM_DAYS, $NUM_MONTHS, $NUM_YEARS;

    if ( $match['year'] < 100 )
    { 
        # two-digit year
        $entropy = logarithm( $NUM_DAYS * $NUM_MONTHS * 100 );
    }
    else
    {
        # four-digit year
        $entropy = logarithm( $NUM_DAYS * $NUM_MONTHS * $NUM_YEARS );
    };
    
    # add two bits for separator selection [/,-,.,etc]
    if ( $match['separator'] )
    {
        $entropy += 2;
    };

    return $entropy;
};

function spatial_entropy( $match )
{
    global $KEYBOARD_STARTING_POSITIONS, 
           $KEYBOARD_AVERAGE_DEGREE, 
           $KEYPAD_STARTING_POSITIONS, 
           $KEYPAD_AVERAGE_DEGREE;

    $layout = $match['graph'];

    if ( $layout === 'qwerty' || $layout === 'dvorak' )
    {
        $s = $KEYBOARD_STARTING_POSITIONS;
        $d = $KEYBOARD_AVERAGE_DEGREE;
    }
    else
    {
        $s = $KEYPAD_STARTING_POSITIONS;
        $d = $KEYPAD_AVERAGE_DEGREE;
    };

    $possibilities = 0;

    $L = strlen( $match['token'] );
    $t = $match['turns'];

    # estimate the number of possible patterns w/ 
    // length L or less with t turns or less.
    for ( $i = 2; $i <= $L; $i++ )
    {
        $possible_turns = min( $t, $i - 1 );

        for ( $j = 1; $j <= $possible_turns; $j++ )
        {
            $possibilities += binomial_coefficient( $i - 1, $j - 1 ) * $s * pow( $d, $j );
        };
    };

    $entropy = logarithm( $possibilities );

    # add extra entropy for shifted keys. (% instead of 5, A instead of a.)
    # math is similar to extra entropy from uppercase letters in dictionary matches.
    if ( $match['shifted_count'] )
    {
        $S = $match['shifted_count'];
        $U = $L - $S; # unshifted count

        $possibilities = 0;

        $len = min( $S, $U );

        for ( $i = 0; $i <= $len; $i++ )
        {
            $possibilities += binomial_coefficient( $S + $U, $i );
        };

        $entropy += logarithm( $possibilities );
    };

    return $entropy;
};

function dictionary_entropy( &$match )
{
    # keep these as properties for display purposes
    $match['base_entropy'] = logarithm( $match['rank'] );
    $match['uppercase_entropy'] = extra_uppercase_entropy( $match );
    $match['l33t_entropy'] = extra_l33t_entropy( $match );

    return $match['base_entropy'] + $match['uppercase_entropy'] + $match['l33t_entropy'];
};

$START_UPPER = '/^[A-Z][^A-Z]+$/';
$END_UPPER   = '/^[^A-Z]+[A-Z]$/';
$ALL_UPPER   = '/^[^a-z]+$/';
$ALL_LOWER   = '/^[^A-Z]+$/';

function extra_uppercase_entropy( $match )
{
    global $START_UPPER, $END_UPPER, $ALL_UPPER, $ALL_LOWER;

    $word = $match['token'];

    if ( preg_match( $ALL_LOWER, $word ) )
    {
        return 0;
    };

    # a capitalized word is the most common capitalization scheme,
    # so it only doubles the search space (uncapitalized + capitalized): 1 extra bit of entropy.
    # allcaps and end-capitalized are common enough too, underestimate as 1 extra bit to be safe.
    foreach ( array( $START_UPPER, $END_UPPER, $ALL_UPPER ) as $i => $regex )
    {
        if ( preg_match( $regex, $word ) )
        {
            return 1;
        };
    };

    # Otherwise calculate the number of ways to capitalize U+L uppercase+lowercase letters with U uppercase letters or
    # less. Or, if there's more uppercase than lower (for e.g. PASSwORD), the number of ways to lowercase U+L letters
    # with L lowercase letters or less.
    $U = 0;
    $L = 0;

    foreach ( str_split( $word ) as $chr )
    {
        if ( preg_match( '/[A-Z]/', $chr ) )
        {
            $U += 1;
        }
        elseif ( preg_match( '/[a-z]/', $chr ) )
        {
            $L += 1;
        };
    };

    $possibilities = 0;

    $len = min( $U, $L );

    for ( $i = 0; $i <= $len; $i++ )
    {
        $possibilities += binomial_coefficient( $U + $L, $i );
    };

    return logarithm( $possibilities );
};

function extra_l33t_entropy( $match )
{
    if ( ! isset( $match['l33t'] ) )
    {
        return 0;
    };

    $possibilities = 0;
    $sub = $match['sub'];

    foreach ( $sub as $subbed => $unsubbed )
    {
        $S = 0;
        $U = 0;

        foreach ( str_split( $match['token'] ) as $chr )
        {
            if ( $chr === ( string ) $subbed )
            {
                $S += 1;
            }
            elseif ( $chr === $unsubbed )
            {
                $U += 1;
            };
        };

        $len = min( $U, $S );

        for ( $i = 0; $i <= $len; $i++ )
        {
            $possibilities += binomial_coefficient( $U + $S, $i );
        };
    };

    # corner: return 1 bit for single-letter subs, 
    # like 4pple -> apple, instead of 0.
    $entropy = logarithm( $possibilities );
    return ( $entropy ? $entropy : 1 );
};

# utilities --------------------------------------------------------------------


function calc_bruteforce_cardinality( $password )
{
    $lower   = FALSE;
    $upper   = FALSE;
    $digits  = FALSE;
    $symbols = FALSE;
    $unicode = FALSE;

    foreach ( str_split( $password ) as $chr )
    {
        $ord = ord( $chr );

        if ( ( 0x30 <= $ord && $ord <= 0x39 ) )
        {
            $digits = TRUE;
        }
        
        if ( ( 0x41 <= $ord && $ord <= 0x5a ) )
        {
            $upper = TRUE;
        }
        
        if ( ( 0x61 <= $ord && $ord <= 0x7a ) )
        {
            $lower = TRUE;
        }
        else
        {
            $symbols = TRUE;
        };
        /*
        elseif ( $ord <= 0x7f )
        {
            $symbols = TRUE;
        }
        else
        {
            $unicode = TRUE;
        };
        */
    };

    $cardinality = 0;
    $cardinality += ( $digits ? 10 : 0 );
    $cardinality += ( $upper ? 26 : 0 );
    $cardinality += ( $lower ? 26 : 0 );
    $cardinality += ( $symbols ? 33 : 0 );
    #$cardinality += ( $unicode ? 100 : 0 );

    return $cardinality;
}

function display_time( $seconds )
{
    $minute = 60;
    $hour = ( $minute * 60 );
    $day = ( $hour * 24 );
    $month = ( $day * 31 );
    $year = ( $month * 12 );
    $century = ( $year * 100 );

    if ( $seconds < $minute )
    {
        return 'instant';
    }
    elseif ( $seconds < $hour  )
    {
        return ( 1 + ceil( $seconds / $minute ) ) . ' minutes';
    }
    elseif ( $seconds < $day )
    {
        return ( 1 + ceil( $seconds / $hour ) ) . ' hours';
    }
    elseif ( $seconds < $month )
    {
        return ( 1 + ceil( $seconds / $day ) ) . ' days';
    }
    elseif ( $seconds < $year )
    {
        return ( 1 + ceil( $seconds / $month ) ) . ' months';
    }
    elseif ( $seconds < $century )
    {
        return ( 1 + ceil( $seconds / $year ) ) . ' years';
    }
    else
    {
        return 'centuries';
    };
};
?>